# 🛡️ Retrieval Augmented Generation for Robust Cyber Defense

A cybersecurity question-answering system powered by **Retrieval-Augmented Generation (RAG)** and a **Neo4j Knowledge Graph**.

This project is being developed as part of **Project School** by a five-member student team.

---

## 📌 Overview

Cybersecurity information is distributed across multiple datasets and knowledge bases. Understanding the relationships between vulnerabilities, weaknesses, attack patterns, and adversarial techniques can be difficult and time-consuming.

This project aims to build a cybersecurity question-answering system that integrates information from:

- **CVE** — Common Vulnerabilities and Exposures
- **CWE** — Common Weakness Enumeration
- **CAPEC** — Common Attack Pattern Enumeration and Classification
- **MITRE ATT&CK**

The information is represented using a **Neo4j knowledge graph**, allowing relationships between cybersecurity entities to be queried using **Cypher**.

Relevant information retrieved from the knowledge graph is then provided as context to a **Large Language Model (LLM)** using a **Retrieval-Augmented Generation (RAG)** pipeline.

The goal is to generate accurate and context-aware answers that help users understand vulnerabilities, weaknesses, attack patterns, ATT&CK techniques, impact scores, exploitability scores, and possible mitigation paths.

---

## 🎯 Objectives

The major objectives of the project are:

- Collect and process cybersecurity information from CVE, CWE, CAPEC, and MITRE ATT&CK.
- Represent cybersecurity entities and their relationships using a knowledge graph.
- Store and manage the knowledge graph using Neo4j.
- Retrieve relevant cybersecurity entities using Cypher queries.
- Build a Retrieval-Augmented Generation pipeline.
- Integrate an LLM with retrieved cybersecurity context.
- Generate context-aware answers to cybersecurity questions.
- Explore relationships between vulnerabilities, weaknesses, attack patterns, and ATT&CK techniques.
- Provide useful information about impact, exploitability, and possible mitigation paths.

---

## 💡 Problem Statement

Security analysts often need to combine information from several cybersecurity knowledge sources when investigating vulnerabilities and attacks.

For example, understanding a vulnerability may require identifying:

1. the **CVE** describing the vulnerability,
2. the corresponding **CWE** weakness,
3. related **CAPEC** attack patterns,
4. associated **MITRE ATT&CK** techniques,
5. vulnerability severity and impact information,
6. and possible mitigation approaches.

Searching and connecting this information manually can be difficult.

This project explores the use of **knowledge graphs and Retrieval-Augmented Generation** to retrieve relevant cybersecurity information and provide it to an LLM for generating context-aware responses.

---

## 🏗️ Proposed Architecture

```text
                    User Query
                        │
                        ▼
              ┌──────────────────┐
              │   Query Layer    │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Cypher Retrieval │
              └────────┬─────────┘
                       │
                       ▼
        ┌─────────────────────────────┐
        │     Neo4j Knowledge Graph   │
        │                             │
        │ CVE ─ CWE ─ CAPEC ─ ATT&CK │
        └─────────────┬───────────────┘
                      │
                      ▼
             Relevant Cyber Context
                      │
                      ▼
              ┌──────────────────┐
              │   RAG Pipeline   │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │       LLM        │
              └────────┬─────────┘
                       │
                       ▼
              Context-Aware Answer
```

The cybersecurity knowledge graph will be constructed using information from multiple sources:

```text
CVE ─────┐
         │
CWE ─────┤
         ├──► Data Processing ──► Neo4j Knowledge Graph
CAPEC ───┤
         │
ATT&CK ──┘
```

---

## 🔎 Example

A user could ask a cybersecurity-related question such as:

```text
What weaknesses and attack patterns are associated with a particular CVE?
```

The proposed workflow is:

```text
User Question
      │
      ▼
Identify Relevant Entities
      │
      ▼
Generate / Execute Cypher Query
      │
      ▼
Neo4j Knowledge Graph
      │
      ▼
Retrieve Relevant Entities + Relationships
      │
      ▼
Construct RAG Context
      │
      ▼
LLM
      │
      ▼
Generated Cybersecurity Answer
```

---

## 🧠 Knowledge Graph

The knowledge graph is intended to represent relationships between cybersecurity concepts.

A simplified conceptual representation could look like:

```text
CVE
 │
 └── related to ──► CWE
                       │
                       └── related to ──► CAPEC
                                             │
                                             └── related to ──► ATT&CK Technique
```

As development progresses, the graph schema and relationships will be refined based on the structure of the selected cybersecurity datasets.

---

## 📚 Cybersecurity Data Sources

### CVE

**Common Vulnerabilities and Exposures (CVE)** provides identifiers for publicly known cybersecurity vulnerabilities.

Example:

```text
CVE-XXXX-XXXXX
```

---

### CWE

**Common Weakness Enumeration (CWE)** describes common software and hardware weakness types that can lead to vulnerabilities.

Example relationship:

```text
CVE
 │
 └── associated weakness ──► CWE
```

---

### CAPEC

**Common Attack Pattern Enumeration and Classification (CAPEC)** describes common attack patterns used by adversaries.

Possible relationship:

```text
CWE
 │
 └── related attack pattern ──► CAPEC
```

---

### MITRE ATT&CK

**MITRE ATT&CK** organizes adversary tactics and techniques observed in cybersecurity.

The project aims to connect relevant ATT&CK information with other cybersecurity entities where supported by the underlying data.

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| **Python** | Core development and data processing |
| **Neo4j** | Knowledge graph database |
| **Cypher** | Querying the Neo4j graph |
| **Knowledge Graphs** | Representing cybersecurity entities and relationships |
| **RAG** | Retrieving relevant context before generation |
| **LLM** | Generating context-aware answers |

Additional libraries and tools will be added as the implementation evolves.

---

## 📂 Proposed Project Structure

```text
rag-cyber-defense/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│   ├── raw/
│   └── processed/
│
├── src/
│   │
│   ├── ingestion/
│   │   ├── cve/
│   │   ├── cwe/
│   │   ├── capec/
│   │   └── attack/
│   │
│   ├── graph/
│   │
│   ├── retrieval/
│   │
│   ├── rag/
│   │
│   └── utils/
│
├── tests/
│
├── docs/
│
└── scripts/
```

This structure is **proposed** and may change as the project architecture is finalized.

---

## ⚙️ Installation

> The project is currently in the initial development stage. Installation instructions will be updated as the implementation progresses.

### 1. Clone the repository

```bash
git clone <repository-url>
```

### 2. Enter the project directory

```bash
cd rag-cyber-defense
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

#### Windows

```bash
.venv\Scripts\activate
```

#### Linux / macOS

```bash
source .venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

The application is currently under development.

Usage instructions will be added after the initial RAG and knowledge-graph pipeline has been implemented.

---

## 🗺️ Development Roadmap

### Phase 1 — Research & Planning

- [ ] Study project requirements
- [ ] Study CVE dataset structure
- [ ] Study CWE dataset structure
- [ ] Study CAPEC dataset structure
- [ ] Study MITRE ATT&CK dataset structure
- [ ] Design initial system architecture
- [ ] Design knowledge graph schema

### Phase 2 — Data Processing

- [ ] Implement CVE data ingestion
- [ ] Implement CWE data ingestion
- [ ] Implement CAPEC data ingestion
- [ ] Implement MITRE ATT&CK data ingestion
- [ ] Clean and normalize cybersecurity data
- [ ] Create relationships between datasets

### Phase 3 — Knowledge Graph

- [ ] Set up Neo4j
- [ ] Define graph nodes
- [ ] Define graph relationships
- [ ] Import cybersecurity entities
- [ ] Import relationships
- [ ] Test Cypher queries
- [ ] Validate graph relationships

### Phase 4 — Retrieval

- [ ] Process user cybersecurity queries
- [ ] Identify relevant entities
- [ ] Retrieve entities from Neo4j
- [ ] Retrieve relationships from Neo4j
- [ ] Format retrieved information as context

### Phase 5 — RAG & LLM

- [ ] Integrate an LLM
- [ ] Build prompt templates
- [ ] Build the RAG pipeline
- [ ] Pass retrieved graph context to the LLM
- [ ] Generate context-aware responses
- [ ] Handle cases where relevant information is unavailable

### Phase 6 — Application

- [ ] Build application interface
- [ ] Connect interface to the RAG pipeline
- [ ] Display generated responses
- [ ] Display relevant cybersecurity entities
- [ ] Improve error handling

### Phase 7 — Evaluation

- [ ] Create test cybersecurity questions
- [ ] Evaluate retrieval quality
- [ ] Evaluate answer relevance
- [ ] Evaluate response accuracy
- [ ] Analyze incorrect or unsupported responses
- [ ] Improve retrieval and prompting

### Phase 8 — Finalization

- [ ] Add automated tests
- [ ] Improve documentation
- [ ] Add architecture diagrams
- [ ] Add application screenshots
- [ ] Prepare final demonstration
- [ ] Complete Project School documentation

---

## 👥 Team

Developed by a **5-member student team** as part of Project School.

| Team Member | Responsibility |
|---|---|
| Member 1 | To be assigned |
| Member 2 | To be assigned |
| Member 3 | To be assigned |
| Member 4 | To be assigned |
| Member 5 | To be assigned |

Responsibilities will be updated as tasks are assigned during development.

---

## 📋 Project Management

Development is tracked using **GitHub Projects, Issues, Milestones, and Pull Requests**.

Our workflow:

```text
Backlog
   │
   ▼
Ready
   │
   ▼
In Progress
   │
   ▼
In Review
   │
   ▼
Done
```

Each significant development task should have a corresponding GitHub Issue.

Example:

```text
Issue #12: Implement CVE data ingestion
```

The developer assigned to the issue creates a feature branch:

```bash
git checkout -b feature/12-cve-ingestion
```

After implementation:

```bash
git add .
git commit -m "feat: implement CVE data ingestion"
git push origin feature/12-cve-ingestion
```

A Pull Request is then created and reviewed before merging into the main branch.

---

## 🌿 Branching Strategy

The `main` branch contains reviewed and stable code.

Development should be performed using separate branches.

### Feature

```text
feature/<issue-number>-<feature-name>
```

Example:

```text
feature/12-cve-ingestion
```

### Bug Fix

```text
fix/<issue-number>-<bug-name>
```

Example:

```text
fix/31-null-cve-description
```

### Documentation

```text
docs/<issue-number>-<description>
```

Example:

```text
docs/8-architecture
```

---

## 📝 Commit Convention

Use clear and meaningful commit messages.

### Features

```text
feat: implement CVE parser
```

### Fixes

```text
fix: handle missing CWE identifiers
```

### Documentation

```text
docs: add knowledge graph architecture
```

### Tests

```text
test: add CVE parser tests
```

### Refactoring

```text
refactor: simplify graph creation logic
```

Avoid vague commits such as:

```text
update
changes
final
final2
test123
```

---

## 🧪 Testing

Testing will be introduced throughout development.

The project will aim to test areas including:

- Data parsing
- Data normalization
- Knowledge graph creation
- Cypher queries
- Retrieval
- RAG pipeline behavior

Testing instructions will be documented as the implementation evolves.

---

## 📊 Evaluation

The final system will be evaluated based on the implemented functionality and project requirements.

Potential areas of evaluation include:

- Correct retrieval of cybersecurity entities
- Correct retrieval of relationships
- Relevance of retrieved context
- Quality of generated responses
- Handling of unsupported queries

Detailed evaluation methodology and metrics will be finalized during development.

---

## 🔐 Security

This project deals with cybersecurity information but is intended primarily for **defensive, educational, and research purposes**.

Sensitive information such as API keys, passwords, Neo4j credentials, and other secrets must **never be committed to the repository**.

Use environment variables for credentials where required.

Example:

```text
.env
```

The `.env` file should be included in `.gitignore`.

---

## 🤝 Contributing

This repository is currently maintained by the Project School team.

Team members should:

1. Select or be assigned a GitHub Issue.
2. Move the issue to **In Progress**.
3. Create a branch for the issue.
4. Implement and test the change.
5. Commit using a meaningful commit message.
6. Push the branch to GitHub.
7. Open a Pull Request.
8. Request review from another team member.
9. Address review comments if necessary.
10. Merge the Pull Request after approval.
11. Move the issue to **Done**.

---

## 📖 Documentation

Project documentation will be maintained in the `docs/` directory.

Planned documentation includes:

```text
docs/
├── architecture.md
├── knowledge-graph.md
├── data-sources.md
├── rag-pipeline.md
└── evaluation.md
```

---

## 📌 Project Status

🚧 **Currently in Initial Development**

The team is currently working on:

- Understanding project requirements
- Studying cybersecurity datasets
- Designing the system architecture
- Designing the knowledge graph
- Setting up the development environment

The README will be updated continuously as development progresses.

---

## ⚠️ Disclaimer

This project is being developed for **academic and educational purposes** as part of Project School.

The system is intended to assist with cybersecurity information retrieval and analysis. Generated responses should not be considered a substitute for professional security assessment or authoritative cybersecurity guidance.

---

## 📄 License

A license has not yet been selected for this project.

---

**Project:** Retrieval Augmented Generation for Robust Cyber Defense  
**Category:** Cybersecurity  
**Team Size:** 5  
**Status:** 🚧 In Development