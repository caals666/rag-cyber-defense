"""Question -> IDs -> Neo4j facts -> Groq answer.

The LLM only sees facts returned by Neo4j and is told to say when something is missing.
"""
import json
import re

from groq import Groq

import config
from graph import queries
from graph.connection import run

ID_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
LOOKUPS = {"CVE": queries.CVE_CHAIN, "CWE": queries.CWE_CHAIN,
           "CAPEC": queries.CAPEC_CHAIN, "T": queries.ATTACK_NODE}
MAX_LIST = 40  # cap long neighbour lists so the prompt stays small

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant.
Answer ONLY from the JSON facts provided, which come from a Neo4j knowledge graph built from
NVD CVE, MITRE CWE, MITRE CAPEC and MITRE ATT&CK data.
Rules:
- Never invent IDs, scores or relationships. If a link is not in the facts, it does not exist in the data.
- Cite IDs in brackets, e.g. [CVE-2024-24919], [CWE-200].
- Structure the answer in three short sections:
  **Retrieved facts** - what the graph returned.
  **Attack-path analysis** - what the connections mean (counts, CWE -> CAPEC -> ATT&CK chains).
  **Not available** - what was asked but is missing from the data.
- If no facts were found, say so plainly."""


def extract_ids(question):
    return list(dict.fromkeys(m.upper() for m in ID_PATTERN.findall(question)))


def trim(value):
    if isinstance(value, list) and len(value) > MAX_LIST:
        return value[:MAX_LIST] + [f"... {len(value) - MAX_LIST} more"]
    return value


def retrieve(question):
    ids = extract_ids(question)
    if ids:
        facts, missing = [], []
        for entity_id in ids:
            prefix = "T" if entity_id.startswith("T") else entity_id.split("-")[0]
            rows = run(LOOKUPS[prefix], id=entity_id)
            first = rows[0] if rows else {}
            if first and list(first.values())[0] is not None:
                facts.append({k: trim(v) for k, v in first.items()})
            else:
                missing.append(entity_id)
        return {"mode": "id_lookup", "ids": ids, "facts": facts, "not_found": missing}

    # No ID in the question: full-text search. Lucene treats symbols as syntax, so keep words only.
    text = " ".join(re.findall(r"\w+", question))
    facts = run(queries.KEYWORD_SEARCH, text=text) if text else []
    return {"mode": "keyword_search", "ids": [], "facts": facts, "not_found": []}


def generate(question, retrieved):
    """Returns (answer, llm_status). An LLM failure never hides the retrieved facts."""
    if not config.GROQ_API_KEY:
        return None, "not configured (set GROQ_API_KEY)"
    try:
        client = Groq(api_key=config.GROQ_API_KEY)
        response = client.chat.completions.create(
            model=config.GROQ_MODEL,
            temperature=0.1,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Question: {question}\n\nFacts:\n{json.dumps(retrieved, default=str)}"},
            ],
        )
        return response.choices[0].message.content, config.GROQ_MODEL
    except Exception as exc:
        return None, f"{config.GROQ_MODEL} failed: {exc}"


def answer(question):
    retrieved = retrieve(question)
    text, llm = generate(question, retrieved)
    return {"question": question, "answer": text, "llm": llm, **retrieved}
