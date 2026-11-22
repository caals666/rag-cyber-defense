# Cyber Defense RAG

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/caals666/rag-cyber-defense)

Ask a cybersecurity question in plain English and get a short answer **built only from real security data**,
with proof. Based on the paper *Retrieval Augmented Generation for Robust Cyber Defense*
(Rahman et. al, PNNL-36792, 2024). A 5-member Project School  team.

---

## 1. The idea in one minute

- **Problem:** a normal AI chatbot guesses. It invents bug IDs and scores and gives no proof.
- **Fix (RAG):** first *find* the real records, then let the AI answer *only* from them.
- **Our data** is a graph of four official MITRE/NVD catalogues, linked in  chain:

```
CVE (a real bug) ──► CWE (the coding mistake) ──► CAPEC (how attackers exploit it) ──► ATT&CK (what they do next)
```

| Word | Simple meaning | Example |
|---|---|---|
| CVE | one specific bug in one product | CVE-2024-24919 (Check Point gateway) |
| CWE | the type of mistake behind bugs | CWE-200 leaking private information |
| CAPEC | a known way to attack a mistake | CAPEC-66 SQL injection |
| ATT&CK | what attackers do after getting in | T1539 steal web session cookie |
| CVSS / severity | danger score 0–10: Low, Medium, High (7–8.9), Critical (9–10) | 8.6 = High |
| CISA KEV | list of bugs attackers really used | 165 of our 2024 CVEs |

---

## 2. How one question is answered

```
Your question
     │
     ▼
Does it name an ID? (CVE-…, CWE-89 or "CWE 89", CAPEC-…, T1234)
     │
     ├── yes ─► ID lookup ─────────► tested Cypher query fetches that record and its chain
     │
     └── no ──► Semantic search ───► the question becomes 384 numbers (all-MiniLM-L6-v2);
                    │                  Neo4j's vector index finds the 5 closest records by meaning,
                    │                  then we follow each one's chain in the graph
                    │
                    └── nothing close enough (score < 0.65) ─► Keyword fallback (full-text search)
     │
     ▼
The records + your question go to the AI (Groq, gpt-oss-120b) with strict rules:
answer in ≤ 5 short lines, use only these facts, never invent IDs.
     │
     ▼
The answer streams back word by word, then a "Verified" check confirms every ID and score
in it really exists in the graph. Off-topic questions get:
"I don't have information about that in the security data."
```

The page shows which way was used as a badge: **ID lookup**, **Semantic search** or **Keyword fallback**.

---

## 3. Where the code is (read in this order)

| File | What it does |
|---|---|
| `frontend/index.html` + `frontend/js/chat.js` | the Ask page: question box, chat, answer, badge |
| `frontend/js/api.js` | sends the question to the backend and reads the streamed answer |
| `backend/api/routes.py` | the API: `/health`, `/cve/{id}`, `/ask`, `/ask/stream` |
| `backend/rag/pipeline.py` | **the brain**: find IDs → pick records → ask the AI → stream events |
| `backend/retrieval/lookup.py` | ID lookup: one ID → its record and chain |
| `backend/retrieval/hybrid.py` | semantic search: closest records by meaning → their chains |
| `backend/rag/embeddings.py` | turns text into 384 numbers with all-MiniLM-L6-v2 |
| `backend/graph/queries.py` | the tested Cypher queries (the AI never writes queries) |
| `backend/rag/prompts.py` | the rules we give the AI |
| `backend/rag/grounding.py` | the "Verified" check |
| `neo4j/*.cypher`, `neo4j/embed_nodes.py` | build the graph, then write an embedding on every node |
| `frontend/js/graph.js` | the attack path map under an answer |
| `frontend/insights.html`, `research.html`, `history.html` | charts, our test results, saved answers |
| `tests/test_pipeline.py` | checks the routing, semantic search and off-topic refusal |

Everything else is looks (`style.css`, `backdrop.js` = the 3D dots) or one-time data scripts.

---

## 4. Run it (Docker)

```bash
cp .env.example .env            # then put your free Groq key in GROQ_API_KEY
docker compose up --build -d    # first run ~15 min: loads the graph, then writes embeddings
docker compose ps               # all running; neo4j-init and embed-init show "Exited (0)" = done
```

| Open | What |
|---|---|
| http://localhost:3000 | the website (plain HTML/CSS/JS served by nginx) |
| http://localhost:8000/docs | the API |
| http://localhost:7474 | Neo4j Browser (user `neo4j`, password `password123`) |

Start order: `neo4j` healthy → `neo4j-init` loads the graph → `backend` → `frontend`. At the same time
`embed-init` writes embeddings in the background (first run: several minutes; later runs skip nodes already
done). Until it exits, questions without an ID use keyword search. Each answer has a small "Cypher" toggle
showing the queries that were run. The AI model is cached in a Docker volume.

```bash
docker compose exec backend python -m pytest tests -q     # run the tests
curl -X POST localhost:8000/ask -H "Content-Type: application/json" \
     -d '{"question":"how do attackers steal login sessions?"}'
```

Settings in `.env`: `GROQ_API_KEY`, `GROQ_MODEL`, `EMBEDDING_MODEL`, `VECTOR_TOP_K` (5), `VECTOR_MIN_SCORE` (0.65).

To run the local API against Aura, put Aura's `neo4j+s://` URI, username and password in the root
`.env`, then start the backend from `backend/` with `python -m uvicorn main:app --reload`. The backend
loads the root `.env` automatically. With Docker Compose, the `backend` and `embed-init` services use
those same settings; if `NEO4J_URI` is empty, they use the local Neo4j service instead. Check
`http://localhost:8000/health` to see which database has been reached and how many nodes it contains.

Online: the same frontend and backend run on Vercel with Neo4j Aura. Vercel deploys the API, but it
does not run the graph-loading script. Load the data into Aura once from the repository root, using
the same Aura instance/database that the deployed backend will use:

```bash
python -m pip install neo4j certifi
python neo4j/load_remote.py
```

`load_remote.py` reads `NEO4J_URI`, `NEO4J_USER` (or `NEO4J_USERNAME`) and `NEO4J_PASSWORD` from
the root `.env` file or the shell environment. **It clears the target graph before loading**, so
check the URI/database first. In Vercel, configure `NEO4J_URI`, `NEO4J_USER` and `NEO4J_PASSWORD`
with credentials for that same Aura database, then redeploy. Check the deployed `/health` endpoint:
it should report about 40,661 nodes, not zero. The loader prints node and relationship totals when
it finishes. Vercel is too small for the embedding model, so online questions without an ID use
keyword search.

---

## 5. The data

- 38,461 CVEs (2024) · 944 CWEs · 559 CAPECs · 697 ATT&CK techniques = **40,661 nodes**, **44,045 links**
- 7 link types: `CVE_CWE`, `CWE_CAPEC`, `CAPEC_ATTACK`, `CWE_CHILD`, `CAPEC_CHILD`, `CAN_PRECEDE`, `SUBTECHNIQUE_OF`
- 10,349 CVEs (27%) connect all the way to an ATT&CK technique; 1,745 have no CWE yet
- Sources: NVD (CVEs, CVSS scores) and MITRE (CWE, CAPEC, ATT&CK); cleaned by `build_datasets.py` into `data/raw/`

---

## 6. What we added to the paper (our results)

The paper showed 4 examples and **no numbers**. We measured it (`backend/eval/`, shown on the Research page):

| 50 questions with answers taken from the graph | GraphRAG (ours) | Same AI, no graph |
|---|---|---|
| Accuracy | 100% | 7% |
| Invented (hallucinated) IDs | 0% | 66% |

**Fix-first score** (`backend/analytics/`, Insights page) ranks which bugs to patch first:
`100 × (CVSS ÷ 10) × (exploitability ÷ 3.9) × (0.5 + 0.5 × reachable ATT&CK techniques ÷ 10)`.
Tested on CISA's list of really exploited bugs: in its top 500 it finds **11**, vs 6 for CVSS alone and about 2 by chance.

Also new: search by meaning, the "Verified" check on every answer, streaming chat with follow-ups
("how do I fix it?" reuses the last IDs), saved history, and a live web app.

---

## 7. Tech stack

| Part | Tool | Why |
|---|---|---|
| Website | plain HTML, CSS, JavaScript, served by nginx | no framework, no build step, easy to read |
| 3D background | three.js (from a CDN) | draws the graph as 9,000 dots in 4 layer colours on a cream background (no dark mode) |
| API | FastAPI (Python) | fast, simple, auto docs at `/docs` |
| Graph database | Neo4j + Cypher | follows CVE → CWE → CAPEC → ATT&CK links in one query |
| Search by meaning | sentence-transformers all-MiniLM-L6-v2 + Neo4j vector indexes | finds records even with different words |
| AI | Groq, `openai/gpt-oss-120b` | fast, free tier |
| Run / host | Docker Compose locally; Vercel + Neo4j Aura online | |

---

## 8. Known limitations

- Data covers CVEs published in 2024 only.
- The 50-question test only uses questions that name an ID; semantic search is not scored yet.
- Groq's free tier allows about 200,000 tokens a day; long answers can wait on its rate limit.
- Online (Vercel) questions without an ID use keyword search, not semantic search.

---

Never commit keys or passwords: keep them in `.env` (git-ignored). For defensive, educational and
research use. MIT licence, see [LICENSE](LICENSE).
