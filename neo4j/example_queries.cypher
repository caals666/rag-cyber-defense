// Example queries for the knowledge graph (build it with schema -> load_graph -> vector_index).
// Replace the example IDs with any CVE / CWE in the data.

// 1. Information about a CVE
MATCH (c:CVE {id: 'CVE-2024-24919'})
RETURN c.id, c.name, c.base_score, c.severity, c.exploitability_score, c.impact_score,
       c.published, c.path_count, c.max_path_depth, c.description;

// 2. CWE weaknesses for a CVE
MATCH (c:CVE {id: 'CVE-2024-24919'})-[r:CVE_CWE]->(w:CWE)
RETURN w.id, w.name, w.category, r.evidence_source;

// 3. CAPEC attack patterns for a CVE (through its CWEs)
MATCH (c:CVE {id: 'CVE-2024-24919'})-[:CVE_CWE]->(w:CWE)-[:CWE_CAPEC]->(p:CAPEC)
RETURN DISTINCT p.id, p.name, p.likelihood, p.severity, w.id AS via_cwe
ORDER BY p.id;

// 4. ATT&CK techniques reachable from a CVE, with the full chain
MATCH (c:CVE {id: 'CVE-2024-24919'})-[:CVE_CWE]->(w:CWE)-[:CWE_CAPEC]->(p:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
RETURN t.id, t.name, t.category AS tactics, collect(DISTINCT w.id + ' > ' + p.id) AS via
ORDER BY t.id;

// 5. All CVEs associated with a CWE
MATCH (c:CVE)-[:CVE_CWE]->(w:CWE {id: 'CWE-79'})
RETURN w.name, count(c) AS cves, avg(c.base_score) AS avg_base_score,
       collect(c.id)[0..5] AS examples;

// 6. CVEs with the highest exploitability scores
MATCH (c:CVE) WHERE c.exploitability_score IS NOT NULL
RETURN c.id, c.name, c.exploitability_score, c.base_score, c.severity
ORDER BY c.exploitability_score DESC, c.base_score DESC
LIMIT 10;

// 7. CVEs connected to the largest number of CAPECs
MATCH (c:CVE)-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(p:CAPEC)
RETURN c.id, c.base_score, count(DISTINCT p) AS capecs
ORDER BY capecs DESC, c.base_score DESC
LIMIT 10;

// 8. Complete CVE -> CWE -> CAPEC -> ATT&CK paths
MATCH (c:CVE)-[:CVE_CWE]->(w:CWE)-[:CWE_CAPEC]->(p:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
RETURN count(*) AS complete_paths, count(DISTINCT c) AS cves_with_complete_path;

// 9. Incomplete paths: where does each CVE's chain stop?
MATCH (c:CVE)
WITH c, CASE
  WHEN NOT EXISTS { (c)-[:CVE_CWE]->() } THEN '1 no CWE mapping'
  WHEN NOT EXISTS { (c)-[:CVE_CWE]->()-[:CWE_CAPEC]->() } THEN '2 CWE has no CAPEC'
  WHEN NOT EXISTS { (c)-[:CVE_CWE]->()-[:CWE_CAPEC]->()-[:CAPEC_ATTACK]->() } THEN '3 CAPEC has no ATT&CK'
  ELSE '4 complete' END AS stops_at
RETURN stops_at, count(*) AS cves ORDER BY stops_at;

// 10. ATT&CK techniques connected to a CWE
// Note: CWE-89, CWE-79, CWE-22 and CWE-78 return no rows. Their CAPECs have no ATT&CK
// mapping in MITRE's CAPEC data, so there is no verified path to report.
MATCH (w:CWE {id: 'CWE-287'})-[:CWE_CAPEC]->(p:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
RETURN t.id, t.name, t.category AS tactics, collect(DISTINCT p.id) AS via_capec
ORDER BY t.id;
