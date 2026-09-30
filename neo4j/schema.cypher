// Constraints and indexes for the cyber knowledge graph.
// Run FIRST, before load_graph.cypher. Safe to re-run (IF NOT EXISTS).
//
//   docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/schema.cypher

// ---------------------------------------------------------------- uniqueness constraints
// One node per ID. Each constraint also creates an index on id, so lookups by ID are fast.
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT attack_id IF NOT EXISTS FOR (n:ATTACK) REQUIRE n.id IS UNIQUE;

// ---------------------------------------------------------------- range indexes
// For filtering and ranking questions ("most exploitable", "critical CVEs", "high-likelihood attacks")
CREATE INDEX cve_severity IF NOT EXISTS FOR (n:CVE) ON (n.severity);
CREATE INDEX cve_base_score IF NOT EXISTS FOR (n:CVE) ON (n.base_score);
CREATE INDEX cve_exploitability IF NOT EXISTS FOR (n:CVE) ON (n.exploitability_score);
CREATE INDEX cve_published IF NOT EXISTS FOR (n:CVE) ON (n.published);
CREATE INDEX cve_path_count IF NOT EXISTS FOR (n:CVE) ON (n.path_count);
CREATE INDEX cwe_category IF NOT EXISTS FOR (n:CWE) ON (n.category);
CREATE INDEX capec_severity IF NOT EXISTS FOR (n:CAPEC) ON (n.severity);
CREATE INDEX capec_likelihood IF NOT EXISTS FOR (n:CAPEC) ON (n.likelihood);
CREATE INDEX attack_type IF NOT EXISTS FOR (n:ATTACK) ON (n.type);

// ---------------------------------------------------------------- full-text index
// Keyword search across names and descriptions, for questions that contain no ID.
// Example:
//   CALL db.index.fulltext.queryNodes('cyber_text', 'printer spooler')
//   YIELD node, score RETURN labels(node)[0], node.id, node.name, score LIMIT 10;
CREATE FULLTEXT INDEX cyber_text IF NOT EXISTS
FOR (n:CVE|CWE|CAPEC|ATTACK) ON EACH [n.name, n.description];
