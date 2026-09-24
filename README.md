# 🛡️ Retrieval Augmented Generation for Robust Cyber Defense

A cybersecurity question-answering system built on a **Neo4j knowledge graph** and **Retrieval-Augmented Generation (RAG)**.

Ask a question in plain English, and the system fetches real facts from a graph of 40,000+ security records and lets an LLM answer using that evidence — instead of guessing.

> Based on: Rahman et al., *"Retrieval Augmented Generation for Robust Cyber Defense"*, Pacific Northwest National Laboratory, **PNNL-36792**, September 2024.
> Developed for **Project School** by a 5-member student team.

---

## 📌 The Problem

To investigate one vulnerability, a security analyst has to connect four separate catalogs by hand:

> *Which weakness caused this bug? How do attackers exploit that weakness? What do real attackers do with it? How do I fix it?*

Plain LLMs can't answer this reliably — they hallucinate CVE details and don't know recent vulnerabilities.

**Our answer:** put all four catalogs into one connected graph, retrieve the real records, and give those to the LLM as evidence.

---

## 🔗 The Core Idea — one chain

```text
CVE  ───────►  CWE  ───────►  CAPEC  ───────►  ATT&CK
the bug      the type of     how it is       what attackers
             mistake         attacked        actually do
```

| Dataset | What it holds | Example |
|---|---|---|
| **CVE** | A specific bug in real software | `CVE-2024-24919` — Check Point gateway leak |
| **CWE** | The *type* of coding mistake | `CWE-79` — Cross-Site Scripting |
| **CAPEC** | *How* attackers exploit it | `CAPEC-66` — SQL Injection attack |
| **ATT&CK** | What attackers do after getting in | `T1566` — Phishing |

CVE comes from **NVD (NIST)**; CWE, CAPEC and ATT&CK come from **MITRE**.

---

## 📊 Current Status of the Data

Both the datasets and the graph are built and loaded. ✅

**Datasets** — in `data/raw/`, built by `build_datasets.py`:

| File | Rows | Key columns |
|---|---|---|
| `cve_dataset.csv` | 38,461 | `id`, `name`, `description`, `base_score`, `exploitability_score`, `impact_score`, `severity`, `related_cwe_ids` |
| `cwe_dataset.csv` | 944 | `id`, `name`, `category`, `description`, `mitigations`, `child_of_ids`, `related_capec_ids` |
| `capec_dataset.csv` | 559 | `id`, `name`, `likelihood`, `severity`, `mitigations`, `child_of_ids`, `can_precede_ids`, `related_cwe_ids`, `related_attack_ids` |
| `attack_dataset.csv` | 697 | `id`, `name`, `type`, `category` (tactic), `platforms`, `mitigations`, `url` |

`id` is the primary key of every dataset. The `*_ids` columns are the foreign keys that join them, and each one becomes a relationship in Neo4j.

**Graph** — 40,661 nodes and 43,570 relationships:

| Nodes | Count | | Relationships | Count |
|---|---:|---|---|---:|
| `:CVE` | 38,461 | | `CVE_CWE` | 40,321 |
| `:CWE` | 944 | | `CWE_CAPEC` | 1,212 |
| `:CAPEC` | 559 | | `CWE_CHILD` | 1,086 |
| `:ATTACK` | 697 | | `CAPEC_CHILD` | 533 |
| | | | `CAN_PRECEDE` | 162 |
| | | | `CAPEC_ATTACK` | 256 |

**10,349 CVEs have the complete chain** from CVE all the way to ATT&CK.

> **Note:** the CVE data currently covers **2024 only**. The paper used all years (242,504 CVEs). Adding the remaining years is a single extra download.

---

## 🏗️ Architecture

```text
   NVD + MITRE                 build_datasets.py                data/raw/*.csv
 (JSON / CSV raw)  ───────►   parse · filter · clean   ───────►   4 datasets
                               extract ID links
                                                                      │
                                                                      ▼
                                                          neo4j/load_graph.cypher
                                                                      │
                                                                      ▼
                            ┌──────────────────────────────────────────────┐
                            │           NEO4J KNOWLEDGE GRAPH              │
                            │   CVE ─► CWE ─► CAPEC ─► ATTACK              │
                            │   + vector index for semantic search         │
                            └──────────────────────────────────────────────┘
                                                                      ▲
  User question ──► Retrieval ──────────────────────────────────────┘
                      │  1. Direct lookup      (ID in question)
                      │  2. Text-to-Cypher     (relationship question)
                      │  3. Hybrid ⭐          (vector + graph)
                      ▼
              Clean the context  (drop embeddings and unused fields)
                      │
                      ▼
                  LLM — Llama 3
                      │
                      ▼
       Grounded answer + citations + attack path + mitigations
                      │
                      ▼
            FastAPI backend ──► Next.js frontend
```

---

## ⭐ What We Add to the Paper

| The paper's gap | What we do |
|---|---|
| **No metrics.** The report gives 4 example screenshots and states there is no aggregate accuracy, F1, latency or hallucination benchmark. | Build **150 test questions with ground truth** and measure accuracy, precision/recall, hallucination rate and latency across 4 systems (plain LLM, CyRAG, GraphCyRAG, Hybrid). |
| **Needs an ID.** Retrieval depends on a CVE/CWE ID appearing in the question. | **Hybrid retrieval** — vector search finds the entry node, then the graph expands from it, so vague questions like *"How do attackers abuse printer services?"* also work. |
| **Notebook only.** Production integration is listed as future work. | A **deployed web app**: Next.js + Supabase auth, Dockerized, with CI via GitHub Actions. |

---

## 🚀 Quick Start

### 1. Start Neo4j in Docker

```bash
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password123 \
  -v neo4j_data:/data -v ${PWD}/import:/import \
  neo4j:5
```

Open **http://localhost:7474** and log in with `neo4j` / `password123`.

### 2. Build the datasets (optional — CSVs are already in `data/raw/`)

Download the raw sources, then:

```bash
python build_datasets.py <raw_dir>
```

| Source | URL |
|---|---|
| CVE | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip` |
| CWE | `https://cwe.mitre.org/data/csv/1000.csv.zip` |
| CAPEC | `https://capec.mitre.org/data/csv/1000.csv.zip` |
| ATT&CK | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` |

### 3. Load the graph

Copy the 4 CSVs into Neo4j's import folder, then:

```bash
docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/load_graph.cypher
```

⚠️ This script **clears the existing graph** before loading.

---

## 🔍 Example Cypher Queries

**Count every node type:**
```cypher
MATCH (n) RETURN labels(n)[0] AS label, count(*) AS nodes ORDER BY nodes DESC
```

**The full attack path for one CVE:**
```cypher
MATCH p=(:CVE {id:'CVE-2024-24919'})-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(:ATTACK)
RETURN p
```

**Find the attacks linked to a weakness:**
```cypher
MATCH (w:CWE {id:'CWE-89'})-[:CWE_CAPEC]->(c:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
RETURN w.name, c.id, c.name, t.id, t.name
```

**The most severe vulnerabilities:**
```cypher
MATCH (c:CVE) WHERE c.base_score >= 9.0
RETURN c.id, c.name, c.base_score ORDER BY c.base_score DESC LIMIT 20
```

---

## 🧠 Key Concepts

**Cybersecurity**
- **Vulnerability** — a flaw an attacker can exploit. **Exploit** — the code that abuses it. **Mitigation** — how you stop it.
- **CVSS** — a 0–10 severity score. **Impact score** — how much damage. **Exploitability score** — how easy to pull off.

**Graph database**
- **Node** — one entity (a CVE, a CWE). **Relationship** — a link between two nodes. **Cypher** — Neo4j's query language, SQL for graphs.
- **Traversal / multi-hop** — following several links in a row, which is what makes the CVE→ATT&CK chain one fast query instead of four SQL joins.

**RAG**
- **Retrieval** — fetch the real facts first. **Generation** — the LLM writes the answer from them.
- **Embedding** — text turned into a list of numbers so similar meanings can be found by distance.
- **Grounding** — tying the answer to retrieved evidence. **Hallucination** — what happens without it.
- **GraphRAG** — retrieving *connected nodes* rather than loose text chunks. That's this project.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Data processing | Python, `json`, `csv`, `re` |
| Graph database | Neo4j 5 (Docker), Cypher |
| Embeddings | `sentence-transformers` (all-MiniLM-L6-v2), Neo4j vector index |
| LLM | Llama 3 via Groq or Ollama |
| Backend | FastAPI, Neo4j Python driver |
| Frontend | Next.js, Supabase (auth), react-force-graph |
| DevOps | Docker, GitHub Actions |

---

## 📂 Project Structure

```text
rag-cyber-defense/
├── README.md
├── build_datasets.py            # raw sources → 4 clean CSVs
├── data/
│   └── raw/
│       ├── cve_dataset.csv
│       ├── cwe_dataset.csv
│       ├── capec_dataset.csv
│       ├── attack_dataset.csv
│       └── inspect_datasets.ipynb
├── neo4j/
│   └── load_graph.cypher        # builds the graph from the CSVs
├── src/                         # planned: ingestion · graph · retrieval · rag
└── LICENSE
```

---

## 🗺️ Roadmap

**Phase 1 — Research & Planning** ✅
- [x] Study the PNNL paper and the 4 datasets
- [x] Design the graph schema

**Phase 2 — Data Processing** ✅
- [x] Ingest CVE, CWE, CAPEC and ATT&CK
- [x] Clean and normalize the data
- [x] Extract the relationships between datasets

**Phase 3 — Knowledge Graph** ✅
- [x] Set up Neo4j in Docker
- [x] Load nodes and all 6 relationship types
- [x] Validate with Cypher queries
- [ ] Add the remaining CVE years (2002–2026)

**Phase 4 — Retrieval** 🚧
- [ ] Set up FastAPI and connect to Neo4j
- [ ] Direct ID lookup (CyRAG)
- [ ] Text-to-Cypher (GraphCyRAG)
- [ ] Embeddings + Neo4j vector index
- [ ] Hybrid retrieval ⭐

**Phase 5 — RAG & LLM**
- [ ] Connect Llama 3 (Groq / Ollama)
- [ ] Prompt templates and context cleaning
- [ ] Answers with citations
- [ ] Handle "no information found"

**Phase 6 — Application**
- [ ] Next.js chat UI + Supabase auth
- [ ] Interactive attack-path graph
- [ ] Docker Compose + CI, then deploy

**Phase 7 — Evaluation** ⭐
- [ ] 150 test questions with ground truth
- [ ] Compare plain LLM vs CyRAG vs GraphCyRAG vs Hybrid
- [ ] Report accuracy, F1, hallucination rate and latency

**Phase 8 — Finalization**
- [ ] Tests, architecture diagrams, screenshots
- [ ] Final report and demo

---

## 👥 Team & Workflow

A 5-member Project School team. Work is tracked with GitHub Issues, Projects and Pull Requests.

```text
Backlog ──► Ready ──► In Progress ──► In Review ──► Done
```

**Branches:** `feature/<issue>-<name>` · `fix/<issue>-<name>` · `docs/<issue>-<name>`

**Commits:** `feat:` · `fix:` · `docs:` · `test:` · `refactor:` — never `update`, `final2` or `test123`.

---

## 🔐 Security & Disclaimer

Never commit API keys, passwords or Neo4j credentials. Keep them in `.env`, which is git-ignored.

This project is for **defensive, educational and research** use as part of Project School. Generated answers are not a substitute for professional security assessment.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

**Project:** Retrieval Augmented Generation for Robust Cyber Defense
**Category:** Cybersecurity · **Team Size:** 5 · **Status:** 🚧 Phase 4 — Retrieval
