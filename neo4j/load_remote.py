"""Load the graph into a remote Neo4j (e.g. AuraDB Free) from the local CSVs.

Aura cannot read file:/// paths, so this runs the same three .cypher files but
sends the CSV rows from this machine: each `LOAD CSV ... FROM 'file:///x.csv' AS row`
becomes `UNWIND $rows AS row`, fed in batches.

    pip install neo4j
    # put NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD in .env (repo root)
    python neo4j/load_remote.py

WARNING: load_graph.cypher clears the target database first.
"""
import csv
import os
import re
import sys
import time
from pathlib import Path

from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "raw"
FILES = ["schema.cypher", "load_graph.cypher", "vector_index.cypher"]
BATCH = 2000
LOAD_CSV = re.compile(r"LOAD CSV WITH HEADERS FROM 'file:///([\w.]+)' AS row")

csv.field_size_limit(10**8)


def read_env():
    """Fill os.environ from the repo's .env without overriding real env vars."""
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def statements(path):
    """Split a .cypher file into statements: drop // comment lines, split on line-ending ';'."""
    text = "\n".join(l for l in path.read_text(encoding="utf-8").splitlines()
                     if not l.lstrip().startswith("//"))
    return [s.strip() for s in re.split(r";\s*(?:\n|$)", text) if s.strip()]


def load_rows(name):
    """CSV rows as dicts, with empty fields as null (matching how LOAD CSV treats them)."""
    with open(DATA / name, encoding="utf-8", newline="") as f:
        return [{k: (v if v != "" else None) for k, v in row.items()} for row in csv.DictReader(f)]


def main():
    read_env()
    uri, user, password = (os.getenv(k) for k in ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"))
    if not uri or "localhost" in uri or not password:
        sys.exit("Set NEO4J_URI (neo4j+s://...), NEO4J_USER and NEO4J_PASSWORD in .env first.")

    cache = {}
    with GraphDatabase.driver(uri, auth=(user or "neo4j", password)) as driver:
        driver.verify_connectivity()
        print(f"Connected to {uri}")
        with driver.session() as session:
            for file in FILES:
                for i, stmt in enumerate(statements(ROOT / "neo4j" / file), 1):
                    start = time.time()
                    match = LOAD_CSV.search(stmt)
                    if match:
                        rows = cache.setdefault(match[1], load_rows(match[1]))
                        query = LOAD_CSV.sub("UNWIND $rows AS row", stmt)
                        for b in range(0, len(rows), BATCH):
                            session.run(query, rows=rows[b:b + BATCH]).consume()
                    else:
                        session.run(stmt).consume()
                    print(f"  {file} #{i} ({time.time() - start:.1f}s)")

            for label, n in session.run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC"):
                print(f"{label:8} {n:>7,} nodes")
            rels = session.run("MATCH ()-[r]->() RETURN count(r) AS n").single()["n"]
            print(f"{'total':8} {rels:>7,} relationships")


if __name__ == "__main__":
    main()
