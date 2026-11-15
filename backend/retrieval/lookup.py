"""Look up one ID in Neo4j and follow its links: CVE -> CWE -> CAPEC -> ATT&CK."""
from graph import queries
from graph.connection import run

# Which tested Cypher query to run for each kind of ID
QUERY_FOR = {"CVE": queries.CVE_CHAIN, "CWE": queries.CWE_CHAIN, "CAPEC": queries.CAPEC_CHAIN, "T": queries.ATTACK_NODE}

MAX_ITEMS = 8   # longest list of linked records we send to the LLM
MAX_PATHS = 10  # paths are short strings, so we keep more of them


def shorten(items, limit):
    """Cut a long list so the prompt stays small, and say how many were left out."""
    if isinstance(items, list) and len(items) > limit:
        return items[:limit] + [f"... {len(items) - limit} more"]
    return items


def lookup(entity_id):
    """The record for one ID with its linked records, paths and counts, or None if it is not in the graph."""
    kind = "T" if entity_id.startswith("T") else entity_id.split("-")[0]
    rows = run(QUERY_FOR[kind], id=entity_id)
    if not rows or list(rows[0].values())[0] is None:
        return None
    record = rows[0]
    fact = {key: shorten(value, MAX_PATHS if key == "paths" else MAX_ITEMS) for key, value in record.items()}
    fact["counts"] = {key: len(value) for key, value in record.items() if isinstance(value, list)}
    return fact
