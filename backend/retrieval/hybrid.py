"""Hybrid retrieval, for questions that name no ID.

1. Vector search: embed the question and ask Neo4j's vector indexes for the nodes closest in meaning
   (the "entry nodes"), keeping only matches above VECTOR_MIN_SCORE.
2. Graph expansion: follow each entry node through CVE -> CWE -> CAPEC -> ATT&CK with the same
   tested Cypher queries as an ID lookup, so every link in the answer comes from the real graph.
"""
import config
from graph.connection import run
from rag import embeddings
from retrieval.lookup import lookup

INDEXES = ["cve_embedding", "cwe_embedding", "capec_embedding", "attack_embedding"]

# The k closest nodes from one vector index. Only plain fields come back, never the embedding itself.
VECTOR_SEARCH = """
CALL db.index.vector.queryNodes($index, $k, $vector) YIELD node, score
WHERE score >= $min_score
RETURN labels(node)[0] AS type, node.id AS id, node.name AS name, round(score, 3) AS score
"""


def entry_nodes(question):
    """The VECTOR_TOP_K nodes closest in meaning to the question, from all four kinds of node."""
    vector = embeddings.embed_query(question)
    hits = []
    for index in INDEXES:
        hits += run(VECTOR_SEARCH, index=index, k=config.VECTOR_TOP_K, vector=vector,
                    min_score=config.VECTOR_MIN_SCORE)
    hits.sort(key=lambda hit: hit["score"], reverse=True)
    return hits[:config.VECTOR_TOP_K]


def search(question):
    """Entry nodes, each expanded into its chain of linked records (no duplicates)."""
    facts, seen = [], set()
    for hit in entry_nodes(question):
        if hit["id"] in seen:
            continue
        seen.add(hit["id"])
        fact = lookup(hit["id"])
        if fact:
            fact["entry"] = hit  # how it was found: type, id, name and similarity score
            facts.append(fact)
    return facts
