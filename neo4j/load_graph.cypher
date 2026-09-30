// Loads the knowledge graph from the four datasets only.
// Run AFTER schema.cypher.
//
// Neo4j's import folder must contain (from data/raw/):
//   cve_dataset.csv, cwe_dataset.csv, capec_dataset.csv, attack_dataset.csv
//
//   docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/load_graph.cypher
//
// Relationships come only from the ID reference columns inside the datasets.
// A link is created only when both endpoints exist (MATCH), so broken references are skipped.
// Every relationship stores the column that proves it (evidence_source).
//
// WARNING: clears all existing nodes and relationships first.

// ---------------------------------------------------------------- reset
MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS;

// ---------------------------------------------------------------- CVE nodes
LOAD CSV WITH HEADERS FROM 'file:///cve_dataset.csv' AS row
CALL (row) {
  CREATE (n:CVE {id: row.id})
  SET n.name = CASE WHEN row.name <> '' THEN row.name END,
      n.description = row.description,
      n.base_score = toFloat(row.base_score),
      n.exploitability_score = toFloat(row.exploitability_score),
      n.impact_score = toFloat(row.impact_score),
      n.severity = CASE WHEN row.severity <> '' THEN row.severity END,
      n.published = date(row.published)
} IN TRANSACTIONS OF 5000 ROWS;

// ---------------------------------------------------------------- CWE nodes
// cwe_dataset.likelihood is empty in the source, so it is not loaded
LOAD CSV WITH HEADERS FROM 'file:///cwe_dataset.csv' AS row
CREATE (n:CWE {id: row.id})
SET n.name = row.name, n.category = row.category, n.description = row.description,
    n.consequences = row.consequences, n.mitigations = row.mitigations;

// ---------------------------------------------------------------- CAPEC nodes
LOAD CSV WITH HEADERS FROM 'file:///capec_dataset.csv' AS row
CREATE (n:CAPEC {id: row.id})
SET n.name = row.name, n.category = row.category, n.description = row.description,
    n.likelihood = CASE WHEN row.likelihood <> '' THEN row.likelihood END,
    n.severity = CASE WHEN row.severity <> '' THEN row.severity END,
    n.mitigations = row.mitigations;

// ---------------------------------------------------------------- ATTACK nodes
LOAD CSV WITH HEADERS FROM 'file:///attack_dataset.csv' AS row
CREATE (n:ATTACK {id: row.id})
SET n.name = row.name, n.type = row.type, n.description = row.description,
    n.category = [x IN split(row.category, ';') WHERE x <> ''],
    n.platforms = [x IN split(row.platforms, ';') WHERE x <> ''],
    n.mitigations = row.mitigations, n.url = row.url;

// ---------------------------------------------------------------- CVE_CWE
LOAD CSV WITH HEADERS FROM 'file:///cve_dataset.csv' AS row
CALL (row) {
  UNWIND [x IN split(coalesce(row.related_cwe_ids, ''), ';') WHERE x <> ''] AS target
  MATCH (a:CVE {id: row.id}), (b:CWE {id: target})
  MERGE (a)-[r:CVE_CWE]->(b)
  SET r.evidence_source = 'cve_dataset.csv:related_cwe_ids', r.mapping_method = 'direct_reference'
} IN TRANSACTIONS OF 5000 ROWS;

// ---------------------------------------------------------------- CWE_CAPEC
// Recorded in both files; MERGE keeps one edge, and it lists both columns as evidence.
LOAD CSV WITH HEADERS FROM 'file:///cwe_dataset.csv' AS row
UNWIND [x IN split(coalesce(row.related_capec_ids, ''), ';') WHERE x <> ''] AS target
MATCH (a:CWE {id: row.id}), (b:CAPEC {id: target})
MERGE (a)-[r:CWE_CAPEC]->(b)
SET r.evidence_source = 'cwe_dataset.csv:related_capec_ids', r.mapping_method = 'direct_reference';

LOAD CSV WITH HEADERS FROM 'file:///capec_dataset.csv' AS row
UNWIND [x IN split(coalesce(row.related_cwe_ids, ''), ';') WHERE x <> ''] AS source
MATCH (a:CWE {id: source}), (b:CAPEC {id: row.id})
MERGE (a)-[r:CWE_CAPEC]->(b)
ON CREATE SET r.evidence_source = 'capec_dataset.csv:related_cwe_ids', r.mapping_method = 'direct_reference'
ON MATCH SET r.evidence_source = CASE WHEN r.evidence_source CONTAINS 'capec_dataset'
  THEN r.evidence_source ELSE 'capec_dataset.csv:related_cwe_ids|' + r.evidence_source END;

// ---------------------------------------------------------------- CAPEC_ATTACK
LOAD CSV WITH HEADERS FROM 'file:///capec_dataset.csv' AS row
UNWIND [x IN split(coalesce(row.related_attack_ids, ''), ';') WHERE x <> ''] AS target
MATCH (a:CAPEC {id: row.id}), (b:ATTACK {id: target})
MERGE (a)-[r:CAPEC_ATTACK]->(b)
SET r.evidence_source = 'capec_dataset.csv:related_attack_ids', r.mapping_method = 'direct_reference';

// ---------------------------------------------------------------- hierarchy and sequence
LOAD CSV WITH HEADERS FROM 'file:///cwe_dataset.csv' AS row
UNWIND [x IN split(coalesce(row.child_of_ids, ''), ';') WHERE x <> ''] AS target
MATCH (a:CWE {id: row.id}), (b:CWE {id: target})
MERGE (a)-[r:CWE_CHILD]->(b)
SET r.evidence_source = 'cwe_dataset.csv:child_of_ids', r.mapping_method = 'direct_reference';

LOAD CSV WITH HEADERS FROM 'file:///capec_dataset.csv' AS row
UNWIND [x IN split(coalesce(row.child_of_ids, ''), ';') WHERE x <> ''] AS target
MATCH (a:CAPEC {id: row.id}), (b:CAPEC {id: target})
MERGE (a)-[r:CAPEC_CHILD]->(b)
SET r.evidence_source = 'capec_dataset.csv:child_of_ids', r.mapping_method = 'direct_reference';

LOAD CSV WITH HEADERS FROM 'file:///capec_dataset.csv' AS row
UNWIND [x IN split(coalesce(row.can_precede_ids, ''), ';') WHERE x <> ''] AS target
MATCH (a:CAPEC {id: row.id}), (b:CAPEC {id: target})
MERGE (a)-[r:CAN_PRECEDE]->(b)
SET r.evidence_source = 'capec_dataset.csv:can_precede_ids', r.mapping_method = 'direct_reference';

// ATT&CK sub-techniques: T1566.001 belongs to T1566 (official ID convention)
MATCH (s:ATTACK {type: 'sub-technique'})
WHERE s.id CONTAINS '.'
MATCH (p:ATTACK {id: split(s.id, '.')[0]})
MERGE (s)-[r:SUBTECHNIQUE_OF]->(p)
SET r.evidence_source = 'attack_dataset.csv:type+id', r.mapping_method = 'id_hierarchy';

// ---------------------------------------------------------------- CVE attack-path metrics
// Computed from the graph itself. The chained OPTIONAL MATCHes walk every path
// CVE -> CWE -> CAPEC -> ATTACK, keeping partial paths where a hop is missing.
MATCH (c:CVE)
CALL (c) {
  OPTIONAL MATCH (c)-[:CVE_CWE]->(w:CWE)
  OPTIONAL MATCH (w)-[:CWE_CAPEC]->(p:CAPEC)
  OPTIONAL MATCH (p)-[:CAPEC_ATTACK]->(t:ATTACK)
  WITH c, count(DISTINCT w) AS cwes, count(DISTINCT p) AS capecs, count(DISTINCT t) AS attacks,
       count(w) AS paths,
       max(CASE WHEN t IS NOT NULL THEN 3 WHEN p IS NOT NULL THEN 2 WHEN w IS NOT NULL THEN 1 ELSE 0 END) AS depth
  SET c.cwe_count = cwes, c.capec_count = capecs, c.attack_count = attacks,
      c.path_count = paths, c.max_path_depth = depth,
      c.mapping_completeness = round(depth / 3.0, 3)
} IN TRANSACTIONS OF 2000 ROWS;
