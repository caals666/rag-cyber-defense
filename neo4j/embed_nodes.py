"""Write an embedding on every node, for search by meaning.  Run once after the graph is loaded:

    python neo4j/embed_nodes.py        (Docker runs it for you as the "embed-init" service)

For every CVE, CWE, CAPEC and ATT&CK node, "name. description" becomes 384 numbers (all-MiniLM-L6-v2),
stored as the node's `embedding` property. Resumable: nodes that already have one are skipped,
so it is safe to run again. Then it makes sure the vector indexes exist (see vector_index.cypher).
"""
import os

from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
INDEX_FOR = {"CVE": "cve_embedding", "CWE": "cwe_embedding", "CAPEC": "capec_embedding", "ATTACK": "attack_embedding"}
BATCH = 500

driver = GraphDatabase.driver(os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                              auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "password123")))


def query(cypher, **params):
    records, _, _ = driver.execute_query(cypher, params)
    return [r.data() for r in records]


def main():
    model = SentenceTransformer(MODEL)
    for label, index in INDEX_FOR.items():
        # 384 numbers per node, compared by cosine similarity (how close two meanings are)
        query(f"""CREATE VECTOR INDEX {index} IF NOT EXISTS FOR (n:{label}) ON (n.embedding)
                  OPTIONS {{ indexConfig: {{ `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' }} }}""")
        rows = query(f"""MATCH (n:{label}) WHERE n.embedding IS NULL
                         RETURN n.id AS id, coalesce(n.name, '') + '. ' + left(coalesce(n.description, ''), 500) AS text""")
        for start in tqdm(range(0, len(rows), BATCH), desc=f"{label} ({len(rows)} to do)"):
            batch = rows[start:start + BATCH]
            vectors = model.encode([row["text"] for row in batch], normalize_embeddings=True).tolist()
            query(f"UNWIND $rows AS row MATCH (n:{label} {{id: row.id}}) SET n.embedding = row.vector",
                  rows=[{"id": row["id"], "vector": vector} for row, vector in zip(batch, vectors)])
    print("Embeddings ready.")
    driver.close()


if __name__ == "__main__":
    main()
