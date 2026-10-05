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

**Built today:** direct lookup (an ID is in the question) and keyword search (no ID, uses the full-text index). Text-to-Cypher and hybrid vector retrieval are the next work. See [How a Question Is Answered Today](#how-a-question-is-answered-today).

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
| | | `SUBTECHNIQUE_OF` | 475 |
| **Total** | **40,661** | **Total** | **44,045** |

`SUBTECHNIQUE_OF` links an ATT&CK sub-technique to its parent (`T1566.001` → `T1566`), taken from the ID itself.

10,349 CVEs have the complete chain from CVE through to ATT&CK.

**Data validation** (checked on every dataset):

- Every `id` has the right format (`CVE-YYYY-NNNN`, `CWE-N`, `CAPEC-N`, `TNNNN[.NNN]`) and none is duplicated.
- Every link column points to the right dataset type, so the order is always CVE → CWE → CAPEC → ATT&CK.
- 71 CVE → CWE references point to CWE categories (for example `CWE-16`, Configuration) that are not in the CWE research view, and 16 CAPEC → ATT&CK references point to techniques missing from the Enterprise ATT&CK set. The loader uses `MATCH` on both ends, so these broken links are skipped rather than creating empty nodes.

The CVE data currently covers 2024 only. The paper used every year (242,504 CVEs); adding the rest is one more download.

---

## What We Add to the Paper

| The paper's gap | What we do |
|---|---|
| No metrics. The report shows four example screenshots and states it has no aggregate accuracy, F1, latency or hallucination benchmark. | Build 150 test questions with known answers and measure accuracy, precision, recall, hallucination rate and latency across four systems. |
| Retrieval needs an ID in the question. | Hybrid retrieval: vector search finds the entry node, then the graph expands from it, so vague questions work too. |
| Notebook only; production use is listed as future work. | A deployed web app with authentication, Docker and CI. |

---

## Live Deployment

| Part | Where it runs | URL |
|---|---|---|
| Frontend (Next.js) | Vercel | https://rag-cyber-defense-ox4x.vercel.app |
| Backend (FastAPI) | Vercel | https://rag-cyber-defense.vercel.app ([/health](https://rag-cyber-defense.vercel.app/health), [/docs](https://rag-cyber-defense.vercel.app/docs)) |
| Knowledge graph | Neo4j AuraDB Free (cloud) | 40,661 nodes, 44,045 relationships |
| LLM | Groq API | `openai/gpt-oss-120b` |

```text
Browser ──► Frontend (Vercel) ──NEXT_PUBLIC_API_URL──► Backend (Vercel) ──NEO4J_URI──► Neo4j Aura
                                                              └──GROQ_API_KEY──► Groq LLM
```

Each part only knows the address of the next one, set through environment variables:

| Setting | Set on | Purpose |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | frontend | backend address (built into the page at build time, so redeploy after changing it) |
| `NEO4J_URI`, `NEO4J_USER` (or `NEO4J_USERNAME`), `NEO4J_PASSWORD` | backend | Aura connection |
| `GROQ_API_KEY`, `GROQ_MODEL`, `GROQ_REASONING_EFFORT` | backend | LLM access and speed |
| `CORS_ORIGINS` | backend | which websites may call the API (the frontend URL) |

The graph was loaded into Aura once with `python neo4j/load_remote.py`, because Aura cannot read local `file:///` CSVs. Every push to `main` redeploys both Vercel projects.

---

## How a Question Is Answered Today

1. **Detect IDs.** A regular expression in `backend/rag/pipeline.py` finds `CVE-…`, `CWE-…`, `CAPEC-…` and `T…` IDs in the question.
2. **Retrieve.**
   - **ID found → direct lookup.** A tested Cypher template from `backend/graph/queries.py` walks CVE → CWE → CAPEC → ATT&CK and returns the records, every real chain as `paths` (for example `CWE-200 -> CAPEC-169 -> T1592`), and the true list sizes as `counts`.
   - **No ID → keyword search.** The `cyber_text` full-text index searches names and descriptions and returns the top 8 matches.
3. **Trim.** Lists longer than 40 items (150 for paths) are cut and end with `"... N more"`, so the prompt stays small. `counts` still gives the real totals.
4. **Generate.** The facts and the question go to Groq with a strict system prompt: use only these facts and never invent IDs, scores or fixes. Answer in simple English for a non-technical reader, as short as the question allows (one word up to 3 sentences), name the 2–3 most damaging items when there are many, and end with what to do when it helps. Unrelated questions get "I don't have information about that in the security data." Temperature is 0.1 and reasoning effort is `medium`. The CVE lookup also sends the weakness's mitigations, so "how do I fix it?" has real material.
5. **Return.** The API returns the answer and the raw facts together, so every claim can be checked.

**`POST /ask` response:**

```json
{
  "question": "Which ATT&CK techniques are reachable from CVE-2024-24919?",
  "answer": "**Retrieved facts** ... (markdown)",
  "llm": "openai/gpt-oss-120b",
  "mode": "id_lookup",
  "ids": ["CVE-2024-24919"],
  "facts": [{
    "cve": {"id": "CVE-2024-24919", "base_score": 8.6, "severity": "HIGH", "...": "..."},
    "cwes": [{"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor"}],
    "capecs": ["... 59 CAPECs"],
    "techniques": ["... 25 ATT&CK techniques"],
    "paths": ["CWE-200 -> CAPEC-169 -> T1592", "..."],
    "counts": {"cwes": 1, "capecs": 59, "techniques": 25, "paths": 66}
  }],
  "not_found": []
}
```

`mode` is `id_lookup` or `keyword_search`. If Groq fails, `answer` is `null` and `llm` holds the error, but the facts are still returned.

**Measured results** (live deployment, October 2026):

| Check | Result |
|---|---|
| CVE-2024-24919 lookup | 1 CWE, 59 CAPECs, 25 ATT&CK techniques, 66 paths |
| `/ask` end to end | about 3.7 s |
| LLM time for a small answer, reasoning `medium` → `low` | 0.9–1.1 s → 0.4–0.7 s |
| Off-topic question ("Who won the 2023 cricket World Cup?") | "I don't have information about that in the security data." |

**Example answers** (current prompt):

| Question | Answer |
|---|---|
| What is the severity of CVE-2024-24919? | High severity, with a CVSS base score of 8.6 out of 10. |
| What is CWE-79? | A coding mistake where a program puts user-controlled data into a web page without properly cleaning it, letting an attacker inject malicious scripts that run in other users' browsers. Prevent it by using frameworks that encode output and by validating all untrusted input. |
| How do I fix CVE-2024-24919? | Install the Check Point security update that patches the information-disclosure bug, then keep the remote-access VPN in a segmented zone with minimum privileges. |
| Is CVE-2024-99999 dangerous? | I don't have information about that in the security data. |

**Problems we hit and how we fixed them:**

| Problem | Fix |
|---|---|
| The LLM said "26 techniques" when there were 25, and invented direct CVE → technique links | Return `paths` (each real chain) and `counts` (true totals), and tell the LLM to use only those |
| Answers were slow | No reasoning text returned, and reasoning effort made a setting (`low` is about 2× faster; `medium`, the default, gives better answers) |
| Answers were long and technical | Rewrote the prompt: simple English, length matched to the question, most damaging items first, the fix at the end; added mitigations to the CVE lookup |
| Deployed backend tried `localhost:7687` | Moved the graph to Neo4j AuraDB and set the `NEO4J_*` variables on Vercel |
| Aura cannot read `file:///` CSVs, and the GitHub repo is private | `neo4j/load_remote.py` reads the CSVs locally and sends the rows in batches of 2,000 |
| `CERTIFICATE_VERIFY_FAILED` on Windows | The Windows certificate store lacked Aura's root CA; the loader verifies with `certifi`'s CA bundle |
| `Unauthorized` from Aura | Aura's file names the user `NEO4J_USERNAME` (and it is the instance ID, not `neo4j`); the code now accepts both names |

**Known limitations:**

- Questions without an ID always pull in 8 loosely matching records, which adds noise to off-topic answers.
- Some answers still use official technique names (for example "Token Impersonation/Theft").
- Groq response time varies: from under 1 s to about 25 s for the same kind of question.
- CVEs cover 2024 only.
- Embeddings are not written yet, so the vector indexes exist but return nothing.
- No authentication, automated tests or benchmark yet.

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
| Graph database | Neo4j 5 (Docker locally, AuraDB Free in production), Cypher |
| Embeddings | `sentence-transformers` (all-MiniLM-L6-v2), Neo4j vector index |
| LLM | Groq API, model `openai/gpt-oss-120b`, reasoning effort `medium` (configurable via `GROQ_MODEL`, `GROQ_REASONING_EFFORT`) |
| Backend | FastAPI, Neo4j Python driver |
| Frontend | Next.js 15, Supabase auth (planned), react-force-graph (planned) |
| Hosting | Vercel (frontend and backend), Neo4j AuraDB Free (graph) |
| DevOps | Docker, Docker Compose, GitHub Actions (planned) |

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
    └── workflows/
        ├── nextjs.yml                       sample GitHub Pages workflow (unused; to be replaced)
        └── ...                   (planned)  CI and weekly data refresh
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
- [x] Load nodes and all seven relationship types
- [x] Validate with Cypher queries and dataset checks
- [x] Load the graph into Neo4j AuraDB (cloud)
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
- [x] Real attack paths and true counts in the context (fixes miscounting)
- [x] Configurable reasoning effort (speed vs answer quality)
- [x] Short, simple-English answers for non-technical readers
- [ ] Context cleaning and token limits for very large results

**Phase 6 — Application**
- [x] Next.js question page
- [x] Docker Compose for the full stack
- [ ] Supabase auth
- [ ] Interactive attack-path graph
- [x] Deployment (Vercel + Neo4j AuraDB)
- [ ] CI

**Phase 7 — Evaluation**
- [ ] 150 test questions with ground truth
- [ ] Compare the four retrieval systems
- [ ] Report accuracy, F1, hallucination rate and latency

**Phase 8 — Finalization**
- [ ] Tests, diagrams and screenshots
- [ ] Final report and demonstration

---

## Study Notes: Mentor Q&A

Short answers to the questions a mentor is likely to ask.

**What problem does the project solve?**
An analyst investigating a vulnerability has to join four catalogs by hand: the bug (CVE), the type of mistake (CWE), how it is attacked (CAPEC) and what attackers do (ATT&CK). We put all four in one graph and let an LLM explain the connections using only real records.

**What do the acronyms mean?**
CVE: Common Vulnerabilities and Exposures. CWE: Common Weakness Enumeration. CAPEC: Common Attack Pattern Enumeration and Classification. ATT&CK: Adversarial Tactics, Techniques, and Common Knowledge. RAG: Retrieval Augmented Generation. LLM: Large Language Model. KG: Knowledge Graph.

**Why a graph database and not SQL?**
The core question is a chain of four hops. In Neo4j that is one traversal pattern, `(:CVE)-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(:ATTACK)`. In SQL it is four joins through link tables, and it gets harder as paths get longer.

**Why RAG? Why not just ask the LLM?**
A plain LLM invents CVE details and does not know vulnerabilities newer than its training data. RAG fetches the real records first and the LLM writes only from them, so every claim can be traced to a node ID.

**What is the difference between RAG and GraphRAG?**
Standard RAG returns text chunks that look similar to the question. GraphRAG returns records that are actually connected in the graph, which is what lets us explain a full attack path.

**Walk me through what happens when I ask a question.**
Regex finds the IDs → a fixed Cypher template fetches the chain from Neo4j → lists are trimmed and counts added → the facts and the question go to Groq with strict rules → the answer and the raw facts come back together. With no ID, the full-text index finds the closest records instead. See [How a Question Is Answered Today](#how-a-question-is-answered-today).

**How do you stop hallucinations?**
The LLM never writes queries and never sees anything except retrieved facts. The system prompt forbids inventing IDs or links. We pass every real chain (`paths`) and the true totals (`counts`) so it does not have to guess. Temperature is 0.1. Missing IDs are listed in `not_found`. If the facts do not answer the question, the LLM must reply "I don't have information about that in the security data." instead of using its own knowledge.

**Who are the answers written for?**
Non-technical readers. The answer is as short as the question allows (one word up to 3 sentences), uses everyday words, names only the 2–3 most damaging items, and ends with what to do. The exact IDs and records are listed under the answer as sources.

**Why doesn't the LLM write the Cypher?**
Fixed, tested templates are always correct and cannot run harmful queries. Text-to-Cypher (the LLM writes the query) is planned for relationship questions that the templates do not cover, and its accuracy will be measured in the evaluation.

**Which LLM do you use, and why Groq?**
`openai/gpt-oss-120b`, an open-weight model, served by Groq because its inference is very fast and it has a free tier. Reasoning effort is a setting: `low` roughly halves LLM time (0.9–1.1 s → 0.4–0.7 s), and `medium` (our default) gives better answers. The model is a setting too, so it can be swapped.

**How did you build the datasets?**
`build_datasets.py` parses the raw NVD JSON and MITRE CSV/JSON, drops rejected CVEs and deprecated or retired entries, keeps the English description and main CVSS score, removes backslashes and quotes (they break Neo4j's CSV loader), and turns MITRE's `::KEY:value::` links into `;`-separated ID lists.

**How are the relationships created?**
Only from the ID columns in the datasets (`related_cwe_ids`, `related_capec_ids`, and so on). A link is created only when both nodes exist, and every relationship stores the column that proves it in `evidence_source`.

**Are the datasets correct?**
Yes. IDs are valid and unique, and links always follow CVE → CWE → CAPEC → ATT&CK. 87 references point outside the datasets (CWE categories, non-Enterprise techniques) and are skipped. The loaded counts match the CSVs exactly.

**How big is the graph?**
40,661 nodes (38,461 CVE, 944 CWE, 559 CAPEC, 697 ATT&CK) and 44,045 relationships across seven types. 10,349 CVEs have the complete chain to ATT&CK.

**Why only 2024 CVEs?**
To keep the build fast while developing. The paper used all years (242,504 CVEs). Adding them means downloading more NVD files and re-running the build; Aura Free's size limits would then need checking.

**What are embeddings and the vector index for?**
An embedding turns text into 384 numbers (model all-MiniLM-L6-v2) so that similar meanings are close together. Vector indexes on each node type are created, but the embeddings are not written yet. They will power hybrid retrieval: vector search finds the starting node, then the graph expands from it.

**How is it deployed?**
Frontend and backend on Vercel, graph on Neo4j AuraDB Free, LLM on Groq, connected by environment variables. CORS allows only the frontend to call the API. Locally, `docker compose up` runs the whole stack. See [Live Deployment](#live-deployment).

**What problems did you face?**
The LLM miscounted and invented links (fixed with `paths` and `counts`), answers were slow (made reasoning effort a setting), answers were long and technical (rewrote the prompt for short, simple English), the deployed backend had no database (moved to Aura), Aura cannot read local files (wrote `load_remote.py`), and Windows failed the TLS check (verified with `certifi`). See the table in [How a Question Is Answered Today](#how-a-question-is-answered-today).

**What does your project add to the paper?**
Measured results (the paper has none), retrieval that works without an ID (keyword search now, hybrid next), and a deployed web app instead of a notebook.

**What is next?**
Text-to-Cypher, embeddings and hybrid retrieval, then a 150-question benchmark comparing a plain-LLM baseline with our retrieval modes on accuracy, F1, hallucination rate and latency. After that: authentication, the interactive attack-path graph, CI and tests.

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
Category: Cybersecurity · Team size: 5 · Status: deployed; Phase 4, Retrieval (text-to-Cypher and hybrid next)
