// Vector indexes for semantic search (the "hybrid" retrieval mode).
// Run AFTER load_graph.cypher. Safe to re-run (IF NOT EXISTS).
//
//   docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/vector_index.cypher
//
// Each node gets an `embedding` property: its description turned into 384 numbers by
// sentence-transformers/all-MiniLM-L6-v2. The embeddings are written by the Python
// backend (planned: backend/retrieval/vector.py); these indexes make them searchable.
// Until embeddings are written, the indexes exist but return no results.
//
// Dimensions must match the embedding model: all-MiniLM-L6-v2 -> 384.

CREATE VECTOR INDEX cve_embedding IF NOT EXISTS
FOR (n:CVE) ON (n.embedding)
OPTIONS { indexConfig: { `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' } };

CREATE VECTOR INDEX cwe_embedding IF NOT EXISTS
FOR (n:CWE) ON (n.embedding)
OPTIONS { indexConfig: { `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' } };

CREATE VECTOR INDEX capec_embedding IF NOT EXISTS
FOR (n:CAPEC) ON (n.embedding)
OPTIONS { indexConfig: { `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' } };

CREATE VECTOR INDEX attack_embedding IF NOT EXISTS
FOR (n:ATTACK) ON (n.embedding)
OPTIONS { indexConfig: { `vector.dimensions`: 384, `vector.similarity_function`: 'cosine' } };

// ---------------------------------------------------------------- how the backend uses them
// $question_embedding is the user's question, embedded with the same model (384 numbers).
//
// 1. Semantic search: the 5 CWEs closest in meaning to the question
//   CALL db.index.vector.queryNodes('cwe_embedding', 5, $question_embedding)
//   YIELD node, score
//   RETURN node.id, node.name, score;
//
// 2. Hybrid: find the closest CWEs by meaning, then follow real edges to ATT&CK.
//    The vector step only picks the starting nodes; every link comes from the graph.
//   CALL db.index.vector.queryNodes('cwe_embedding', 3, $question_embedding)
//   YIELD node AS w, score
//   OPTIONAL MATCH (w)-[:CWE_CAPEC]->(p:CAPEC)
//   OPTIONAL MATCH (p)-[:CAPEC_ATTACK]->(t:ATTACK)
//   RETURN w.id, w.name, score, collect(DISTINCT p.id) AS capecs, collect(DISTINCT t.id) AS techniques;
//
// Remember: strip n.embedding from results before sending them to the LLM.
