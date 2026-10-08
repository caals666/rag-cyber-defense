# The Fifth Dataset: `cyber_attack_path_dataset.csv`

An analytical dataset that follows how a real vulnerability connects to attack behaviour:

```text
CVE  ──CVE_CWE──►  CWE  ──CWE_CAPEC──►  CAPEC  ──CAPEC_ATTACK──►  ATT&CK
the bug          the weakness        the attack pattern       the attacker technique
```

It is built by `build_attack_path_dataset.py` from the four source datasets in `data/raw/`. Every number in this document comes from the generated files in `data/processed/`.

---

## 1. What the fifth dataset represents

Each row is **one verified attack path** that starts at a CVE and follows recorded references as far as the data allows. The dataset answers a question none of the four source files can answer alone: *starting from this vulnerability, which weaknesses, attack patterns and attacker techniques are reachable, and how complete is that chain?*

| | |
|---|---|
| Rows | 286,890 |
| Columns | 33 (19 original, 14 derived) |
| Unique CVEs | 38,461 (every CVE in the source, none dropped) |
| Unique CWEs / CAPECs / ATT&CK techniques | 545 / 437 / 164 |
| Complete CVE → CWE → CAPEC → ATT&CK paths | 74,498, across 10,349 CVEs |
| File size | 72.6 MB |

---

## 2. Why it is not a merge of the four datasets

| A raw merge would... | The fifth dataset instead... |
|---|---|
| Stack or cross-join rows, creating pairs that are not related | Joins only along edges listed in reference columns; every hop is checked against `cyber_relationships.csv` |
| Keep all 37 source columns, including long free text | Keeps 19 analytical attributes and leaves long text (descriptions, mitigations) in the source files, reachable by ID |
| Describe single entities | Describes **connections between four entities** |
| Drop or fake missing links | Keeps partial paths as partial, with the missing part empty and labelled |
| Add nothing new | Adds 12 derived features about path depth, reach and completeness |

A Cartesian product of the four files would have 38,461 × 944 × 559 × 697 ≈ 14 trillion rows. The fifth dataset has 286,890 because only real chains are followed.

---

## 3. What one row represents

One row = one path `CVE → CWE → CAPEC → ATT&CK`, cut short where the data stops:

| `path_type` | Meaning | Rows |
|---|---|---:|
| `CVE_CWE_CAPEC_ATTACK` | Full chain to an attacker technique | 74,498 |
| `CVE_CWE_CAPEC` | Reaches an attack pattern; that pattern has no ATT&CK mapping | 202,282 |
| `CVE_CWE` | Reaches a weakness; that weakness has no attack pattern | 8,365 |
| `CVE_ONLY` | The CVE lists no resolvable CWE | 1,745 |

A CVE with several paths appears on several rows. `CVE-2024-24919` has 66 rows because its one weakness (CWE-200) leads to 59 attack patterns, 25 of which reach ATT&CK.

---

## 4 – 6. Every feature

### Original features (19), copied unchanged from a source dataset

| Column | Source | Why it is useful |
|---|---|---|
| `cve_id` | cve_dataset.id | Path start; primary key back to the source |
| `cve_name` | cve_dataset.name | Official name; only present for 164 CVEs, since NVD names only some |
| `cve_base_score` | cve_dataset.base_score | Overall CVSS severity, 0–10 |
| `cve_severity` | cve_dataset.severity | Severity band (LOW … CRITICAL) |
| `cve_exploitability_score` | cve_dataset.exploitability_score | How easy the bug is to exploit |
| `cve_impact_score` | cve_dataset.impact_score | How much damage a successful exploit does |
| `cve_published` | cve_dataset.published | When the CVE became public |
| `cwe_id`, `cwe_name` | cwe_dataset.id, name | The weakness on this path |
| `cwe_category` | cwe_dataset.category | Abstraction level: Pillar, Class, Base or Variant |
| `capec_id`, `capec_name` | capec_dataset.id, name | The attack pattern on this path |
| `capec_category` | capec_dataset.category | Abstraction level: Meta, Standard or Detailed |
| `capec_likelihood` | capec_dataset.likelihood | How likely the attack is |
| `capec_severity` | capec_dataset.severity | How severe the attack is |
| `attack_id`, `attack_name` | attack_dataset.id, name | The ATT&CK technique on this path |
| `attack_type` | attack_dataset.type | technique or sub-technique |
| `attack_tactics` | attack_dataset.category | The attacker goal(s), e.g. privilege-escalation |

### Derived features (14), each calculated only from verified edges

| Column | Level | Definition | Why it is useful |
|---|---|---|---|
| `path_id` | row | Sequential ID, `P000001` … | Stable row reference |
| `path_type` | row | Which hops exist (table in section 3) | Filter complete vs partial paths |
| `path_depth` | row | Number of hops present, 0–3 | How far this path reaches |
| `has_cwe`, `has_capec`, `has_attack` | row | Whether each hop exists | Simple flags for filtering and modelling |
| `cve_cwe_count` | CVE | Distinct CWEs linked to the CVE | Breadth of weaknesses |
| `cve_capec_count` | CVE | Distinct CAPECs reachable from the CVE | Breadth of attack patterns |
| `cve_attack_count` | CVE | Distinct ATT&CK techniques reachable | Breadth of attacker options |
| `cve_path_count` | CVE | Number of paths of depth ≥ 1 | Overall attack-path reach |
| `cve_max_path_depth` | CVE | Deepest path the CVE reaches, 0–3 | Whether the CVE ever reaches ATT&CK |
| `cve_mapping_completeness` | CVE | `cve_max_path_depth / 3` | 0 = no mapping, 1 = full chain exists |
| `cwe_capec_count` | CWE | Distinct CAPECs linked to the row's CWE | How "attackable" that weakness is |
| `capec_attack_count` | CAPEC | Distinct techniques linked to the row's CAPEC | How operational that pattern is |

### Features deliberately left out

| Feature | Reason |
|---|---|
| CWE likelihood | `cwe_dataset.likelihood` is empty for all 944 rows. It is empty in MITRE's own CWE CSV, so there is nothing to use. |
| Descriptions and mitigations | Long text repeated across up to 120 rows per CVE would inflate the file past GitHub's 100 MB limit without adding analytical value. They stay in the source files and on the Neo4j nodes, reachable by ID. |
| Known-exploited flag | `cve_name` is only filled for some CVEs, but the dataset does not state why, so a flag would be an assumption. |
| ATT&CK platforms | Platform lists describe the technique rather than the path; they remain on the ATTACK node. |
| Per-path evidence text | Each hop has exactly one evidence column, so `path_type` already identifies the evidence. Per-edge evidence is in `cyber_relationships.csv`. |

---

## 7. How relationships were discovered

Every relationship comes from an **explicit ID listed in a reference column**. Text similarity is never used.

| Relationship | Source → Target | Evidence column | Method | Valid edges |
|---|---|---|---|---:|
| `CVE_CWE` | CVE → CWE | `cve_dataset.related_cwe_ids` | direct reference | 40,321 |
| `CWE_CAPEC` | CWE → CAPEC | `cwe_dataset.related_capec_ids` **and** `capec_dataset.related_cwe_ids` | direct reference | 1,212 |
| `CAPEC_ATTACK` | CAPEC → ATT&CK | `capec_dataset.related_attack_ids` | direct reference | 256 |
| `CWE_CHILD` | CWE → parent CWE | `cwe_dataset.child_of_ids` | direct reference | 1,086 |
| `CAPEC_CHILD` | CAPEC → parent CAPEC | `capec_dataset.child_of_ids` | direct reference | 533 |
| `CAN_PRECEDE` | CAPEC → following CAPEC | `capec_dataset.can_precede_ids` | direct reference | 162 |
| `SUBTECHNIQUE_OF` | ATT&CK sub-technique → parent | `attack_dataset.type` + `id` | ID hierarchy | 475 |
| **Total** | | | | **44,045** |

Notes:

- **CWE_CAPEC is recorded twice.** Both files list the same 1,212 links (the CAPEC side contains 2 repeated IDs). They were merged into one edge each, and every edge keeps both columns as evidence.
- **SUBTECHNIQUE_OF** uses ATT&CK's own ID convention: a row whose `type` is `sub-technique` and whose ID is `T1566.001` belongs to parent `T1566`. It is created only when the parent row exists in the dataset.
- An edge is kept only when **both endpoints exist** in the datasets.

---

## 8. Relationships that could not be established

**Unresolved references.** These are listed in the data but point to IDs that are not in the datasets. They are reported in `data_quality_report.txt`, not silently removed.

| Relationship | Unresolved | Why |
|---|---:|---|
| `CVE_CWE` | 71 references → 17 IDs | CWE categories, views or deprecated entries (e.g. CWE-16, CWE-264, CWE-310). These are not part of the CWE weakness list. |
| `CAPEC_ATTACK` | 15 references → 10 IDs | Not in the current Enterprise ATT&CK release: revoked/deprecated techniques (e.g. T1562.001) or another matrix (T1513 is Mobile). |

**Relationships not directly available in the supplied datasets:**

| Relationship | Status |
|---|---|
| CVE → CAPEC directly | Relationship not directly available in supplied datasets. It is only reachable through CWE. |
| CVE → ATT&CK directly | Relationship not directly available in supplied datasets. |
| CVE → CVE | Relationship not directly available in supplied datasets. |
| ATT&CK → CAPEC reverse mapping | Relationship not directly available in supplied datasets. `attack_dataset` has no CAPEC column. |
| ATT&CK technique → mitigation entity | Mitigations are names in a text column, not IDs, so no mitigation nodes are created. |

**A real gap to be aware of.** Several of the most common web weaknesses never reach ATT&CK. **CWE-89 (SQL injection), CWE-79 (XSS), CWE-22 (path traversal) and CWE-78 (OS command injection)** all link to attack patterns, but none of those patterns has an ATT&CK mapping in MITRE's CAPEC data. This is why 202,282 rows stop at CAPEC. The system must report this as unavailable, never fill it in.

---

## 9. How the dataset supports Neo4j

`cyber_relationships.csv` is the graph's edge list, and the four source files are its node lists. `neo4j/schema.cypher`, `neo4j/load_graph.cypher` and `neo4j/vector_index.cypher` build the graph from them, and the fifth dataset adds pre-computed metrics to each CVE node.

### Node schema

| Label | Identifier | Properties | Constraint |
|---|---|---|---|
| `CVE` | `id` | name, description, base_score, exploitability_score, impact_score, severity, published, **cwe_count, capec_count, attack_count, path_count, max_path_depth, mapping_completeness** | `REQUIRE n.id IS UNIQUE` |
| `CWE` | `id` | name, category, description, consequences, mitigations | `REQUIRE n.id IS UNIQUE` |
| `CAPEC` | `id` | name, category, description, likelihood, severity, mitigations | `REQUIRE n.id IS UNIQUE` |
| `ATTACK` | `id` | name, type, description, category (tactic list), platforms, mitigations, url | `REQUIRE n.id IS UNIQUE` |

The bold CVE properties come from the fifth dataset.

### Relationship schema

Every relationship carries `evidence_source` and `mapping_method`, so any answer can cite the exact column that proves it.

| Relationship | From → To | Count in graph |
|---|---|---:|
| `CVE_CWE` | CVE → CWE | 40,321 |
| `CWE_CAPEC` | CWE → CAPEC | 1,212 |
| `CAPEC_ATTACK` | CAPEC → ATTACK | 256 |
| `CWE_CHILD` | CWE → CWE | 1,086 |
| `CAPEC_CHILD` | CAPEC → CAPEC | 533 |
| `CAN_PRECEDE` | CAPEC → CAPEC | 162 |
| `SUBTECHNIQUE_OF` | ATTACK → ATTACK | 475 |

The loaded graph was checked against the CSVs. It contains 40,661 nodes and 44,045 relationships, and graph queries reproduce the dataset's counts exactly (74,498 complete paths across 10,349 CVEs).

### Files

| File | Purpose |
|---|---|
| `neo4j/schema.cypher` | Uniqueness constraints, range indexes and a full-text index |
| `neo4j/load_graph.cypher` | All four node types, all seven relationship types, derived CVE metrics |
| `neo4j/vector_index.cypher` | 384-dimension cosine vector indexes for semantic search |
| `neo4j/example_queries.cypher` | Ten tested example queries |

---

## 10. How the dataset supports Graph RAG

```text
USER QUESTION
      ↓
QUESTION UNDERSTANDING        what is being asked: facts, links, ranking, or a gap?
      ↓
ENTITY / ID EXTRACTION        regex for CVE-, CWE-, CAPEC-, T#### IDs
      ↓
CYPHER QUERY GENERATION       choose a tested template; LLM writes Cypher only as a fallback
      ↓
NEO4J RETRIEVAL               read-only query
      ↓
CONNECTED CYBERSECURITY FACTS nodes + edges + evidence_source on each edge
      ↓
CONTEXT CLEANING              drop unused fields; label every fact by type
      ↓
LLM                           answers only from the supplied context
      ↓
EVIDENCE-GROUNDED ANSWER
```

**Rules that keep answers honest**

1. **Templates before free Cypher.** The ten tested queries cover most questions. LLM-written Cypher is a fallback and must be read-only (`MATCH`/`RETURN` only).
2. **The LLM may not add relationships.** If a link was not returned by Neo4j, the answer must not state it.
3. **Every answer is split into three labelled parts:**

| Part | Content | Example |
|---|---|---|
| **Retrieved facts** | Node properties and edges exactly as returned | "CVE-2024-24919 is linked to CWE-200 (source: `cve_dataset.related_cwe_ids`)." |
| **Derived graph information** | Counts and paths computed by the graph | "It reaches 25 ATT&CK techniques through 59 attack patterns." |
| **Unavailable information** | Missing hops, stated plainly | "No ATT&CK mapping exists for CWE-89's attack patterns in the data." |

The fifth dataset helps retrieval in two ways. Its CVE-level metrics are stored on the nodes, so ranking questions such as "which CVEs have the most attack paths" become simple property lookups. Its `path_type` tells the system in advance whether a full chain exists, so the answer can name a missing hop instead of guessing.

---

## 11. Questions the system can answer

Every example below was checked against the current data.

| # | Question | Answered by |
|---|---|---|
| 1 | What weaknesses are associated with CVE-2024-24919? | Query 2 → CWE-200 |
| 2 | Which attack patterns are connected to CVE-2024-24919? | Query 3 → 59 CAPECs |
| 3 | Which ATT&CK techniques are reachable from CVE-2024-24919? | Query 4 → 25 techniques |
| 4 | What is the complete attack path for this vulnerability? | Query 4, with the `via` chain |
| 5 | Which CVEs have high exploitability **and** many attack paths? | `exploitability_score ≥ 3.9 AND path_count ≥ 10` → 1,990 CVEs |
| 6 | Which weaknesses connect to the most attack patterns? | `cwe_capec_count` → CWE-200 (59), CWE-20 (51), CWE-74 (37) |
| 7 | Which ATT&CK techniques appear across the most vulnerabilities? | T1574.007 (2,328 CVEs), T1574.006 (2,118) |
| 8 | Why is this vulnerability important from an attack-path perspective? | `path_count`, `attack_count`, `max_path_depth` + severity scores |
| 9 | How many CVEs are linked to CWE-79 (XSS)? | Query 5 → 7,929 CVEs |
| 10 | Which CVEs reach the largest number of attack patterns? | Query 7 → CVE-2024-36471 (107) |
| 11 | Which CVEs have no weakness mapping at all? | Query 9 → 1,745 CVEs |
| 12 | Which ATT&CK techniques are linked to CWE-287 (Improper Authentication)? | Query 10 → 8 techniques |
| 13 | Does SQL injection (CWE-89) lead to any ATT&CK technique? | Query 10 → none; reported as unavailable |
| 14 | What attack patterns can follow CAPEC-1? | `CAN_PRECEDE` → CAPEC-17 |
| 15 | What is the parent weakness of CWE-5? | `CWE_CHILD` → CWE-319 |
| 16 | Which attacker tactics does CVE-2024-24919 enable? | Query 4 → `attack_tactics` (mostly discovery) |
| 17 | Which sub-techniques belong to T1574 (Hijack Execution Flow)? | `SUBTECHNIQUE_OF` |
| 18 | What share of 2024 CVEs can be traced all the way to ATT&CK? | 10,349 of 38,461 (26.9%) |

---

## 12. Validation

These checks were run on the generated files, and all passed.

| Check | Result |
|---|---|
| Every CVE_CWE, CWE_CAPEC and CAPEC_ATTACK hop in the path dataset exists in the relationship file | 0 violations |
| Every relationship endpoint exists in its source dataset | 0 violations |
| Every ID in the path dataset traces back to a source row | 0 violations |
| Duplicate relationships / path rows / path IDs | 0 / 0 / 0 |
| Source CVEs missing from the path dataset | 0 |
| Paths with a gap (e.g. ATT&CK without CAPEC) | 0 |
| `cve_cwe_count` recomputed independently from the relationship file | 0 mismatches |
| Graph counts match the dataset (complete paths, CVEs per `path_type`) | Match |

---

## Limitations

- **2024 CVEs only.** Adding more years means downloading more NVD files and re-running both build scripts.
- **ATT&CK coverage is thin.** Only 256 CAPEC→ATT&CK links exist, so 73% of CVEs cannot be traced to an attacker technique. This is a limit of MITRE's mappings, not of the pipeline.
- **CWE likelihood is unavailable** in the source data.
- **NVD CWE assignments vary in precision.** Some CVEs are mapped to broad classes (CWE-200, CWE-20), which reach many attack patterns. A high `cve_capec_count` can mean a broad mapping rather than a more dangerous bug.
- **Paths show possibility, not activity.** A path means an attack is *documented as possible*, not that it has been seen in the wild.

---

## Output files

| File | Contents |
|---|---|
| `data/processed/cyber_attack_path_dataset.csv` | The fifth dataset |
| `data/processed/cyber_relationships.csv` | 44,045 verified edges with evidence |
| `data/processed/dataset_inspection_report.txt` | Step 1 inspection of all four sources |
| `data/processed/data_quality_report.txt` | Row counts, duplicates, unresolved references, coverage |
| `data/processed/pipeline_output.txt` | Full console output of the last run |
| `neo4j/schema.cypher`, `load_graph.cypher`, `vector_index.cypher` | Graph build scripts, run in that order |
| `neo4j/example_queries.cypher` | Ten tested queries |
| `build_attack_path_dataset.py` | Rebuilds everything above from `data/raw/` |
