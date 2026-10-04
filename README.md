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
                       LLM (Groq)   
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

The whole system runs with Docker Compose: Neo4j, a one-time graph loader, the FastAPI backend and the Next.js frontend.

**Requirements:** Docker Desktop, and a free Groq API key from https://console.groq.com/keys

**1. Configure**

```bash
cp .env.example .env
```

Open `.env` and set `GROQ_API_KEY`. Never commit `.env`.

**2. Build and start everything**

```bash
docker compose up --build -d
```

On the first start, the `neo4j-init` service builds the graph from the four CSVs in `data/raw/` (about 30 seconds). Later starts skip this because the graph is already stored in the `neo4j_data` volume.

**3. Open**

| Service | URL |
|---|---|
| Frontend (ask questions) | http://localhost:3000 |
| Backend API docs | http://localhost:8000/docs |
| Backend health check | http://localhost:8000/health |
| Neo4j Browser | http://localhost:7474 (`neo4j` / password from `.env`) |

### Docker commands

| Task | Command |
|---|---|
| Build all images | `docker compose build` |
| Build one image | `docker compose build backend` |
| Start everything | `docker compose up -d` |
| Rebuild after code changes | `docker compose up --build -d` |
| Rebuild and restart one service | `docker compose up --build -d backend` |
| See running services | `docker compose ps` |
| Follow logs | `docker compose logs -f backend` |
| Check the graph load | `docker compose logs neo4j-init` |
| Stop (keeps the graph) | `docker compose down` |
| Stop and delete the graph | `docker compose down -v` |
| Reload the graph from scratch | `docker compose down -v` then `docker compose up -d` |
| Cypher shell | `docker compose exec neo4j cypher-shell -u neo4j -p password123` |
| Run a Cypher file | `docker compose exec -T neo4j cypher-shell -u neo4j -p password123 < neo4j/example_queries.cypher` |

Build a single image without Compose:

```bash
docker build -t rag-cyber-backend ./backend
docker build -t rag-cyber-frontend --build-arg NEXT_PUBLIC_API_URL=http://localhost:8000 ./frontend
```

### Try the API

```bash
curl http://localhost:8000/health
curl http://localhost:8000/cve/CVE-2024-24919
curl -X POST http://localhost:8000/ask -H "Content-Type: application/json" \
     -d '{"question": "Which ATT&CK techniques are reachable from CVE-2024-24919?"}'
```

### Run without Docker (development)

```bash
# backend, with Neo4j running from compose
cd backend
pip install -r requirements.txt
uvicorn main:app --reload            # http://localhost:8000

# frontend
cd frontend
npm install
npm run dev                          # http://localhost:3000
```

### Loading the graph into Neo4j Aura (deployment)

Aura cannot read local files, so `neo4j/load_remote.py` sends the CSV rows from your machine. Put the Aura `NEO4J_URI`, `NEO4J_USER` and `NEO4J_PASSWORD` in `.env`, then:

```bash
python neo4j/load_remote.py
```

It clears the target database first, then runs `schema.cypher`, `load_graph.cypher` and `vector_index.cypher`.

### Rebuilding the datasets (optional)

The four CSVs are already in `data/raw/`. To regenerate them, download the sources and run `python build_datasets.py <raw_dir>`.

| Source | URL |
|---|---|
| CVE | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip` |
| CWE | `https://cwe.mitre.org/data/csv/1000.csv.zip` |
| CAPEC | `https://capec.mitre.org/data/csv/1000.csv.zip` |
| ATT&CK | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` |

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
MATCH (w:CWE {id:'CWE-287'})-[:CWE_CAPEC]->(c:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
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
| Data processing | Python, pandas, `json`, `csv`, `re` |
| Graph database | Neo4j 5 (Docker), Cypher |
| Embeddings | `sentence-transformers` (all-MiniLM-L6-v2), Neo4j vector index |
| LLM | Groq API, model `openai/gpt-oss-120b` (configurable via `GROQ_MODEL`) |
| Backend | FastAPI, Neo4j Python driver |
| Frontend | Next.js 15, Supabase auth (planned), react-force-graph (planned) |
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
├── .env.example                             template for secrets (copy to .env)
├── docker-compose.yml                       neo4j + graph loader + backend + frontend
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
│       ├── cyber_attack_path_dataset.csv    (git-ignored, 70 MB; regenerate)
│       ├── cyber_relationships.csv
│       ├── dataset_inspection_report.txt
│       ├── data_quality_report.txt
│       └── pipeline_output.txt
│
├── neo4j/
│   ├── schema.cypher                        1. constraints and indexes
│   ├── load_graph.cypher                    2. nodes and relationships
│   ├── vector_index.cypher                  3. vector indexes
│   ├── load_remote.py                       runs 1-3 against Neo4j Aura from local CSVs
│   └── example_queries.cypher               10 tested queries
│
├── backend/                                 FastAPI
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                              app entry point, CORS
│   ├── config.py                            settings from env vars
│   ├── graph/
│   │   ├── connection.py                    Neo4j driver
│   │   └── queries.py                       tested Cypher templates
│   ├── rag/
│   │   ├── pipeline.py                      IDs -> Neo4j -> Groq answer
│   │   └── prompts.py                       LLM prompt templates
│   ├── api/
│   │   └── routes.py                        /health, /cve/{id}, /ask
│   └── retrieval/                (planned)  text-to-Cypher, vector, hybrid
│
├── frontend/                                Next.js
│   ├── Dockerfile
│   ├── package.json
│   ├── next.config.mjs
│   ├── app/
│   │   ├── layout.jsx
│   │   ├── page.jsx                         question box, answer, facts
│   │   └── globals.css
│   ├── components/               (planned)  graph view, cards
│   └── lib/                      (planned)  API client, Supabase auth
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
- [x] Set up FastAPI and connect to Neo4j
- [x] Direct ID lookup
- [x] Keyword search (full-text index) for questions with no ID
- [ ] Text-to-Cypher
- [ ] Embeddings and the Neo4j vector index
- [ ] Hybrid retrieval

**Phase 5 — RAG and LLM**
- [x] Connect the LLM (Groq, gpt-oss-120b)
- [x] Grounded prompt template
- [x] Answers with citations
- [x] Handle "no information found"
- [ ] Context cleaning and token limits for very large results

**Phase 6 — Application**
- [x] Next.js question page
- [x] Docker Compose for the full stack
- [ ] Supabase auth
- [ ] Interactive attack-path graph
- [ ] CI and deployment

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
