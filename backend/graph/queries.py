"""Tested Cypher templates. The LLM never writes queries here; it only reads the results."""

CVE_CHAIN = """
MATCH (c:CVE {id: $id})
OPTIONAL MATCH (c)-[:CVE_CWE]->(w:CWE)
OPTIONAL MATCH (w)-[:CWE_CAPEC]->(p:CAPEC)
OPTIONAL MATCH (p)-[:CAPEC_ATTACK]->(t:ATTACK)
RETURN c {.id, .name, .description, .base_score, .severity, .exploitability_score,
          .impact_score, .path_count, .max_path_depth, published: toString(c.published)} AS cve,
       collect(DISTINCT w {.id, .name, .category}) AS cwes,
       collect(DISTINCT p {.id, .name, .likelihood, .severity}) AS capecs,
       collect(DISTINCT t {.id, .name, tactics: t.category}) AS techniques
"""

CWE_CHAIN = """
MATCH (w:CWE {id: $id})
OPTIONAL MATCH (w)-[:CWE_CAPEC]->(p:CAPEC)
OPTIONAL MATCH (p)-[:CAPEC_ATTACK]->(t:ATTACK)
WITH w, collect(DISTINCT p {.id, .name, .likelihood, .severity}) AS capecs,
     collect(DISTINCT t {.id, .name, tactics: t.category}) AS techniques
RETURN w {.id, .name, .category, .description, .mitigations} AS cwe, capecs, techniques,
       COUNT { (:CVE)-[:CVE_CWE]->(w) } AS cve_count
"""

CAPEC_CHAIN = """
MATCH (p:CAPEC {id: $id})
OPTIONAL MATCH (w:CWE)-[:CWE_CAPEC]->(p)
OPTIONAL MATCH (p)-[:CAPEC_ATTACK]->(t:ATTACK)
OPTIONAL MATCH (p)-[:CAN_PRECEDE]->(n:CAPEC)
RETURN p {.id, .name, .description, .likelihood, .severity, .mitigations} AS capec,
       collect(DISTINCT w.id) AS cwes,
       collect(DISTINCT t {.id, .name, tactics: t.category}) AS techniques,
       collect(DISTINCT n.id) AS can_precede
"""

ATTACK_NODE = """
MATCH (t:ATTACK {id: $id})
OPTIONAL MATCH (p:CAPEC)-[:CAPEC_ATTACK]->(t)
RETURN t {.id, .name, .type, .description, .mitigations, tactics: t.category} AS technique,
       collect(DISTINCT p.id) AS capecs
"""

# For questions with no ID: keyword search over names and descriptions
KEYWORD_SEARCH = """
CALL db.index.fulltext.queryNodes('cyber_text', $text) YIELD node, score
RETURN labels(node)[0] AS type, node.id AS id, node.name AS name,
       left(node.description, 300) AS description, round(score, 2) AS score
LIMIT 8
"""
