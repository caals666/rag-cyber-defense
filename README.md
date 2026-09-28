# Retrieval Augmented Generation for Robust Cyber Defense

A cybersecurity question-answering system built on a **Neo4j knowledge graph** and **Retrieval-Augmented Generation (RAG)**.

Ask a question in plain English. The system finds the real security records, follows their connections in the graph, and gives those facts to an LLM so the answer is based on evidence instead of guesswork.

Based on: Rahman et al., *Retrieval Augmented Generation for Robust Cyber Defense*, Pacific Northwest National Laboratory, PNNL-36792, September 2024.
Developed for Project School by a 5-member student team.

---

## The Problem

To investigate one vulnerability, an analyst has to connect four separate catalogs by hand:

> Which weakness caused this bug? How do attackers exploit that weakness? What do real attackers do with it? How do I fix it?

A plain LLM cannot answer this reliably. It invents CVE details and does not know recent vulnerabilities.

Our solution is to put all four catalogs into one connected graph, retrieve the real records, and hand them to the LLM as evidence.

---

## The Core Idea

```text
CVE  ───────►  CWE  ───────►  CAPEC  ───────►  ATT&CK
the bug      the type of     how it is       what attackers
             mistake         attacked        actually do
```

| Dataset | What it holds | Example | Source |
|---|---|---|---|
| CVE | A specific bug in real software | `CVE-2024-24919` | NVD (NIST) |
| CWE | The type of coding mistake | `CWE-79` (Cross-Site Scripting) | MITRE |
| CAPEC | How attackers exploit it | `CAPEC-66` (SQL Injection) | MITRE |
| ATT&CK | What attackers do after getting in | `T1566` (Phishing) | MITRE |

---

## Architecture

The system has two halves. The **build stage** runs once and prepares the graph. The **query stage** runs every time a user asks something.

### Stage 1 — Build (offline)

```text
   RAW SOURCES                 PROCESSING                  CLEAN DATASETS
 ┌───────────────┐        ┌──────────────────┐         ┌─────────────────┐
 │ NVD CVE  JSON │        │ build_datasets.py│         │ cve_dataset.csv │
 │ CWE      CSV  │  ───►  │  1. parse        │  ───►   │ cwe_dataset.csv │
 │ CAPEC    CSV  │        │  2. filter       │         │ capec_dataset...│
 │ ATT&CK   JSON │        │  3. select fields│         │ attack_datase...│
 └───────────────┘        │  4. clean text   │         └────────┬────────┘
                          │  5. extract links│                  │
                          └──────────────────┘                  │
                                                                ▼
                                                  neo4j/load_graph.cypher
                                                                │
                                                                ▼
                    ┌───────────────────────────────────────────────────┐
                    │              NEO4J KNOWLEDGE GRAPH                │
                    │                                                   │
                    │   (:CVE) ──CVE_CWE──► (:CWE) ──CWE_CAPEC──►       │
                    │   (:CAPEC) ──CAPEC_ATTACK──► (:ATTACK)            │
                    │                                                   │
                    │   40,661 nodes · 43,570 relationships             │
                    └───────────────────────────────────────────────────┘
                                                                ▲
                                                                │
                    ┌───────────────────────────────────────────┴───────┐
                    │  EMBEDDING STEP                                   │
                    │  descriptions ──► all-MiniLM-L6-v2 ──► vectors    │
                    │  stored on each node · Neo4j vector index         │
                    └───────────────────────────────────────────────────┘
```

**The five processing steps**

1. **Parse** — read the raw JSON and CSV files.
2. **Filter** — drop rejected CVEs, deprecated CAPECs and retired ATT&CK techniques.
3. **Select fields** — keep the English description and the primary CVSS score.
4. **Clean text** — remove backslashes and quotes, which break Neo4j's CSV loader.
5. **Extract links** — pull the related IDs out of MITRE's `::KEY:value::` format into simple `;`-separated lists.

### Stage 2 — Query (live)

```text
                         USER QUESTION
                "Find the CAPECs related to CVE-2024-24919"
                               │
                               ▼
                          ROUTER
              Does the question contain an ID?
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
  DIRECT LOOKUP         TEXT-TO-CYPHER           HYBRID (new)
  ID is present         relationship question    no ID / vague
                                                 1. vector search
  MATCH (c:CVE          LLM writes the              finds entry node
  {id:...})             Cypher query             2. graph expands
  RETURN c              and runs it              3. results merged
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ▼
                       CONTEXT CLEANING
           remove embeddings and unused fields; keep
           ids, descriptions, scores and mitigations
                               │
                               ▼
                       LLM (Llama 3)
              prompt = cleaned facts + user question
                               │
                               ▼
                      GROUNDED ANSWER
         explanation + citations + attack path + mitigations
                               │
                               ▼
            FastAPI backend ──────► Next.js frontend
                                    chat UI, auth, graph view
```

---

## RAG Architecture

RAG means the model retrieves real facts before it writes an answer. It has two phases: indexing, which runs once, and querying, which runs on every question.

### Phase 1 — Indexing (offline, done once)

```text
  DATA SOURCES          CHUNKING            EMBEDDING MODEL         VECTOR STORE
 ┌─────────────┐     ┌─────────────┐      ┌────────────────┐     ┌──────────────┐
 │ documents / │ ──► │ split into  │ ───► │ text -> vector │ ──► │ index of     │
 │ datasets    │     │ small parts │      │ 384 numbers    │     │ vectors + ids│
 └─────────────┘     └─────────────┘      └────────────────┘     └──────────────┘
```

In this project the "chunks" are node descriptions (CVE, CWE, CAPEC, ATT&CK), and the vector store is Neo4j's built-in vector index, so the vectors live on the nodes themselves.

### Phase 2 — Querying (live, every question)

```text
   USER QUESTION
         │
         ▼
   EMBED THE QUESTION          same model as indexing
         │
         ▼
   SIMILARITY SEARCH           cosine similarity, top-k matches
         │
         ▼
   RE-RANK (optional)          put the best evidence first
         │
         ▼
   BUILD THE PROMPT            retrieved facts + question + instructions
         │
         ▼
   LLM GENERATES               writes the answer using only those facts
         │
         ▼
   ANSWER + CITATIONS          every claim traceable to a record
```

### Why the LLM needs this

| Without RAG | With RAG |
|---|---|
| Answers from memory alone | Answers from retrieved records |
| Invents CVE numbers and scores | Quotes the real score from the graph |
| Frozen at its training cutoff | As current as the last data refresh |
| No sources | Cites the node IDs it used |

### Standard RAG vs our GraphRAG

```text
STANDARD RAG                        OUR GRAPHRAG
question                            question
   │                                   │
   ▼                                   ▼
vector search                       vector search finds the entry node
   │                                   │
   ▼                                   ▼
top-k text chunks                   graph traversal follows the links
   │                                CVE -> CWE -> CAPEC -> ATT&CK
   ▼                                   │
LLM answer                             ▼
                                    connected records -> LLM answer
```

Standard RAG returns text that merely *looks* similar to the question. GraphRAG returns records that are genuinely *connected* to each other, which is what lets the system explain a full attack path rather than just describing one vulnerability.

The three retrieval modes in Stage 2 above are the concrete implementation: direct lookup when an ID is given, text-to-Cypher for relationship questions, and hybrid for everything else.

---

## Current Status of the Data

The datasets and the graph are built and loaded.

**Datasets** in `data/raw/`, produced by `build_datasets.py`:

| File | Rows | Key columns |
|---|---:|---|
| `cve_dataset.csv` | 38,461 | `id`, `name`, `description`, `base_score`, `exploitability_score`, `impact_score`, `severity`, `related_cwe_ids` |
| `cwe_dataset.csv` | 944 | `id`, `name`, `category`, `description`, `mitigations`, `child_of_ids`, `related_capec_ids` |
| `capec_dataset.csv` | 559 | `id`, `name`, `likelihood`, `severity`, `mitigations`, `child_of_ids`, `can_precede_ids`, `related_cwe_ids`, `related_attack_ids` |
| `attack_dataset.csv` | 697 | `id`, `name`, `type`, `category`, `platforms`, `mitigations`, `url` |

`id` is the primary key of every dataset. The `*_ids` columns are the foreign keys that join the datasets together, and each one becomes a relationship in Neo4j.

**Graph contents:**

| Nodes | Count | Relationships | Count |
|---|---:|---|---:|
| `:CVE` | 38,461 | `CVE_CWE` | 40,321 |
| `:CWE` | 944 | `CWE_CAPEC` | 1,212 |
| `:CAPEC` | 559 | `CWE_CHILD` | 1,086 |
| `:ATTACK` | 697 | `CAPEC_CHILD` | 533 |
| | | `CAN_PRECEDE` | 162 |
| | | `CAPEC_ATTACK` | 256 |

10,349 CVEs have the complete chain from CVE through to ATT&CK.

The CVE data currently covers 2024 only. The paper used every year (242,504 CVEs); adding the rest is one more download.

---

## What We Add to the Paper

| The paper's gap | What we do |
|---|---|
| No metrics. The report shows four example screenshots and states it has no aggregate accuracy, F1, latency or hallucination benchmark. | Build 150 test questions with known answers and measure accuracy, precision, recall, hallucination rate and latency across four systems. |
| Retrieval needs an ID in the question. | Hybrid retrieval: vector search finds the entry node, then the graph expands from it, so vague questions work too. |
| Notebook only; production use is listed as future work. | A deployed web app with authentication, Docker and CI. |

---

## Quick Start

**1. Start Neo4j in Docker**

```bash
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password123 \
  -v neo4j_data:/data -v ${PWD}/import:/import \
  neo4j:5
```

Open http://localhost:7474 and log in with `neo4j` / `password123`.

**2. Build the datasets** (optional, the CSVs are already in `data/raw/`)

```bash
python build_datasets.py <raw_dir>
```

| Source | URL |
|---|---|
| CVE | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip` |
| CWE | `https://cwe.mitre.org/data/csv/1000.csv.zip` |
| CAPEC | `https://capec.mitre.org/data/csv/1000.csv.zip` |
| ATT&CK | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` |

**3. Build the fifth dataset** (optional, the outputs are already in `data/processed/`)

```bash
python build_attack_path_dataset.py
```

**4. Load the graph**

Copy the four `data/raw/` CSVs plus `cyber_relationships.csv` and `cyber_attack_path_dataset.csv` into Neo4j's import folder, then run the three scripts in order:

```bash
docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/schema.cypher
docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/load_graph.cypher
docker exec -i neo4j cypher-shell -u neo4j -p password123 < neo4j/vector_index.cypher
```

`load_graph.cypher` clears the existing graph before loading. Tested queries are in `neo4j/example_queries.cypher`.

---

## Example Cypher Queries

Count every node type:

```cypher
MATCH (n) RETURN labels(n)[0] AS label, count(*) AS nodes ORDER BY nodes DESC
```

The full attack path for one CVE:

```cypher
MATCH p=(:CVE {id:'CVE-2024-24919'})-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(:ATTACK)
RETURN p
```

Attacks linked to a weakness:

```cypher
MATCH (w:CWE {id:'CWE-89'})-[:CWE_CAPEC]->(c:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
RETURN w.name, c.id, c.name, t.id, t.name
```

The most severe vulnerabilities:

```cypher
MATCH (c:CVE) WHERE c.base_score >= 9.0
RETURN c.id, c.name, c.base_score ORDER BY c.base_score DESC LIMIT 20
```

---

## Key Concepts

**Cybersecurity**

- **Vulnerability** — a flaw an attacker can exploit. **Exploit** — the code that abuses it. **Mitigation** — how you stop it.
- **CVSS** — a 0 to 10 severity score. **Impact score** — how much damage. **Exploitability score** — how easy it is to pull off.

**Graph database**

- **Node** — one entity, such as a CVE. **Relationship** — a link between two nodes. **Cypher** — Neo4j's query language, which is SQL for graphs.
- **Traversal** — following several links in a row. This is what turns the CVE-to-ATT&CK chain into one fast query instead of four SQL joins.

**RAG**

- **Retrieval** — fetch the real facts first. **Generation** — the LLM writes the answer from them.
- **Embedding** — text turned into numbers so similar meanings can be found by distance.
- **Grounding** — tying the answer to retrieved evidence. **Hallucination** — what happens without it.
- **GraphRAG** — retrieving connected nodes instead of loose text chunks. That is this project.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Data processing | Python, `json`, `csv`, `re` |
| Graph database | Neo4j 5 (Docker), Cypher |
| Embeddings | `sentence-transformers` (all-MiniLM-L6-v2), Neo4j vector index |
| LLM | Llama 3 via Groq or Ollama |
| Backend | FastAPI, Neo4j Python driver |
| Frontend | Next.js, Supabase (auth), react-force-graph |
| DevOps | Docker, Docker Compose, GitHub Actions |

---

## Project Structure

This is the final target layout. Items marked `(planned)` do not exist yet.

```text
rag-cyber-defense/
│
├── README.md
├── LICENSE
├── .gitignore
├── .env.example                  (planned)  template for secrets
├── requirements.txt              (planned)
├── docker-compose.yml            (planned)  neo4j + backend + frontend
│
├── build_datasets.py                        raw sources -> 4 clean CSVs
├── build_attack_path_dataset.py             4 CSVs -> fifth dataset + reports
│
├── data/
│   ├── raw/                                 the 4 datasets
│   │   ├── cve_dataset.csv
│   │   ├── cwe_dataset.csv
│   │   ├── capec_dataset.csv
│   │   ├── attack_dataset.csv
│   │   └── inspect_datasets.ipynb
│   └── processed/                           fifth dataset and reports
│       ├── cyber_attack_path_dataset.csv
│       ├── cyber_relationships.csv
│       ├── dataset_inspection_report.txt
│       ├── data_quality_report.txt
│       └── pipeline_output.txt
│
├── neo4j/
│   ├── schema.cypher                        1. constraints and indexes
│   ├── load_graph.cypher                    2. nodes and relationships
│   ├── vector_index.cypher                  3. vector indexes
│   └── example_queries.cypher               10 tested queries
│
├── backend/                      (planned)
│   ├── main.py                              FastAPI entry point
│   ├── config.py                            settings and env vars
│   ├── graph/
│   │   ├── connection.py                    Neo4j driver
│   │   └── queries.py                       reusable Cypher
│   ├── retrieval/
│   │   ├── direct.py                        ID lookup
│   │   ├── text_to_cypher.py                question -> Cypher
│   │   ├── vector.py                        embeddings + similarity
│   │   └── hybrid.py                        vector + graph merge
│   ├── rag/
│   │   ├── prompts.py                       prompt templates
│   │   ├── context.py                       cleaning, citations
│   │   └── pipeline.py                      retrieve -> generate
│   └── api/
│       └── routes.py                        /ask, /graph, /cve/{id}
│
├── frontend/                     (planned)
│   ├── app/                                 Next.js pages
│   ├── components/                          chat, graph view, cards
│   └── lib/                                 API client, Supabase auth
│
├── evaluation/                   (planned)
│   ├── questions.json                       150 questions + ground truth
│   ├── run_benchmark.py                     compares the 4 systems
│   └── results/                             metrics and charts
│
├── tests/                        (planned)
│   ├── test_datasets.py
│   ├── test_graph.py
│   └── test_retrieval.py
│
├── docs/
│   ├── fifth_dataset_documentation.md       the fifth dataset, explained
│   ├── architecture.md           (planned)
│   ├── knowledge-graph.md        (planned)
│   ├── data-sources.md           (planned)
│   ├── rag-pipeline.md           (planned)
│   └── evaluation.md             (planned)
│
└── .github/
    └── workflows/                (planned)  CI and weekly data refresh
```

---

## Roadmap

**Phase 1 — Research and planning** (done)
- [x] Study the PNNL paper and the four datasets
- [x] Design the graph schema

**Phase 2 — Data processing** (done)
- [x] Ingest CVE, CWE, CAPEC and ATT&CK
- [x] Clean and normalize the data
- [x] Extract the relationships between datasets

**Phase 3 — Knowledge graph** (done)
- [x] Set up Neo4j in Docker
- [x] Load nodes and all six relationship types
- [x] Validate with Cypher queries
- [ ] Add the remaining CVE years

**Phase 4 — Retrieval** (current)
- [ ] Set up FastAPI and connect to Neo4j
- [ ] Direct ID lookup
- [ ] Text-to-Cypher
- [ ] Embeddings and the Neo4j vector index
- [ ] Hybrid retrieval

**Phase 5 — RAG and LLM**
- [ ] Connect Llama 3
- [ ] Prompt templates and context cleaning
- [ ] Answers with citations
- [ ] Handle "no information found"

**Phase 6 — Application**
- [ ] Next.js chat interface with Supabase auth
- [ ] Interactive attack-path graph
- [ ] Docker Compose, CI and deployment

**Phase 7 — Evaluation**
- [ ] 150 test questions with ground truth
- [ ] Compare the four retrieval systems
- [ ] Report accuracy, F1, hallucination rate and latency

**Phase 8 — Finalization**
- [ ] Tests, diagrams and screenshots
- [ ] Final report and demonstration

---

## Team and Workflow

A 5-member Project School team. Work is tracked with GitHub Issues, Projects and Pull Requests.

```text
Backlog ──► Ready ──► In Progress ──► In Review ──► Done
```

Branches: `feature/<issue>-<name>`, `fix/<issue>-<name>`, `docs/<issue>-<name>`

Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`. Avoid `update`, `final2` and `test123`.

---

## Security and Disclaimer

Never commit API keys, passwords or Neo4j credentials. Keep them in `.env`, which is git-ignored.

This project is for defensive, educational and research use as part of Project School. Generated answers are not a substitute for professional security assessment.

---

## License

MIT. See [LICENSE](LICENSE).

---

Project: Retrieval Augmented Generation for Robust Cyber Defense
Category: Cybersecurity · Team size: 5 · Status: Phase 4, Retrieval
