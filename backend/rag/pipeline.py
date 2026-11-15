"""How a question becomes an answer, in four steps:

1. find_ids       pull IDs like "CVE-2024-24919" or "CWE 89" out of the question
2. retrieve       pick the records: ID lookup, or search by meaning (hybrid), or keyword search
3. stream_llm     send the question and records to the LLM and get its answer back piece by piece
4. answer_stream  wrap it all as events the website shows as they arrive
"""
import json
import re

from groq import Groq

import config
from graph import queries
from graph.connection import run
from rag import embeddings
from rag.grounding import check as grounding_check
from rag.prompts import DETAILS_PROMPT, REFUSAL, SYSTEM_PROMPT
from retrieval import hybrid
from retrieval.lookup import lookup

# CVE-2024-24919, CWE-79 or "CWE 79", CAPEC-66 or "CAPEC 66", and ATT&CK IDs like T1036 or T1574.008
ID_PATTERN = re.compile(r"\b(CVE[-\s]\d{4}-\d{4,}|CWE[-\s]\d+|CAPEC[-\s]\d+|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
MAX_TURNS = 6  # earlier questions and answers we send back, so follow-ups make sense

client = Groq(api_key=config.GROQ_API_KEY) if config.GROQ_API_KEY else None


def find_ids(text):
    """'Is cwe 89 bad?' -> ['CWE-89'] (each ID once, upper case, with a dash)."""
    ids = (re.sub(r"\s", "-", match.upper()) for match in ID_PATTERN.findall(text))
    return list(dict.fromkeys(ids))


def is_follow_up(question):
    """Short questions that point back with words like "it" or "this" ("how do I fix it?")."""
    words = re.findall(r"[a-z']+", question.lower())
    return len(words) <= 12 and any(w in {"it", "its", "it's", "this", "that", "these", "those", "them", "they"} for w in words)


# One short line per query we ran, so the website can show the Cypher behind each answer
SHORT_CYPHER = {
    "CVE": "MATCH (:CVE {{id:'{id}'}})-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(:ATTACK)",
    "CWE": "MATCH (:CWE {{id:'{id}'}})-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(:ATTACK)",
    "CAPEC": "MATCH (:CWE)-[:CWE_CAPEC]->(:CAPEC {{id:'{id}'}})-[:CAPEC_ATTACK]->(:ATTACK)",
    "T": "MATCH (:CAPEC)-[:CAPEC_ATTACK]->(:ATTACK {{id:'{id}'}})",
}


def short_cypher(entity_id):
    kind = "T" if entity_id.startswith("T") else entity_id.split("-")[0]
    return SHORT_CYPHER[kind].format(id=entity_id)


def retrieve(question, history=()):
    """Find the graph records the question is about. `mode` says which of the three ways was used."""
    ids = find_ids(question)
    # A follow-up like "how do I fix it?" points back at the last answer: reuse that turn's IDs
    if not ids and is_follow_up(question):
        for turn in reversed(history[-2:]):
            ids = find_ids(turn.get("question", "") + " " + turn.get("answer", ""))[:3]
            if ids:
                break

    # 1. The question names IDs: look each one up directly
    if ids:
        facts = [lookup(entity_id) for entity_id in ids]
        return {"mode": "id_lookup", "ids": ids, "cypher": [short_cypher(i) for i in ids],
                "facts": [fact for fact in facts if fact],
                "not_found": [entity_id for entity_id, fact in zip(ids, facts) if not fact]}

    # 2. No ID: search by meaning, then follow the graph (needs the embedding model, installed in Docker)
    if embeddings.available():
        try:
            facts = hybrid.search(question)
            if facts:
                cypher = [f"CALL db.index.vector.queryNodes('<label>_embedding', {config.VECTOR_TOP_K}, $vector) "
                          f"WHERE score >= {config.VECTOR_MIN_SCORE}"]
                cypher += [short_cypher(fact["entry"]["id"]) for fact in facts]
                return {"mode": "hybrid_vector", "ids": [], "cypher": cypher, "facts": facts, "not_found": []}
        except Exception:
            pass  # e.g. embeddings not built yet: fall back to keyword search

    # 3. Fallback: keyword search over names and descriptions. The index treats symbols as syntax, so keep words only.
    words = " ".join(re.findall(r"\w+", question))
    facts = run(queries.KEYWORD_SEARCH, text=words) if words else []
    cypher = [f"CALL db.index.fulltext.queryNodes('cyber_text', '{words}') LIMIT 8"]
    return {"mode": "keyword_search", "ids": [], "cypher": cypher, "facts": facts, "not_found": []}


def build_messages(prompt, question, retrieved, history=()):
    """The chat we send to the LLM: instructions, earlier turns, then the question with its facts."""
    messages = [{"role": "system", "content": prompt}]
    for turn in history[-MAX_TURNS:]:
        messages.append({"role": "user", "content": turn.get("question", "")})
        messages.append({"role": "assistant", "content": turn.get("answer", "")})
    facts = json.dumps({k: v for k, v in retrieved.items() if k != "cypher"}, default=str)  # the LLM doesn't need the queries
    messages.append({"role": "user", "content": f"Question: {question}\n\nFacts:\n{facts}"})
    return messages


def stream_llm(messages):
    """Yield the LLM's answer in small pieces while it is still writing."""
    # gpt-oss "thinks" before answering; low effort is faster, and we don't need the thinking text back
    thinking = ({"reasoning_effort": config.GROQ_REASONING_EFFORT, "include_reasoning": False}
                if config.GROQ_REASONING_EFFORT else {})
    for attempt in range(2):  # now and then the model sends nothing, so try once more
        stream = client.chat.completions.create(
            model=config.GROQ_MODEL, messages=messages, temperature=0.1, stream=True, **thinking)
        sent_something = False
        for chunk in stream:
            piece = chunk.choices[0].delta.content if chunk.choices else None
            if piece:
                sent_something = True
                yield piece
        if sent_something:
            return


def answer_stream(question, history=(), explain=True):
    """Events for the website, in order: facts, answer pieces, details pieces, done."""
    retrieved = retrieve(question, history)
    yield {"type": "facts", **retrieved}
    if client is None:
        yield {"type": "error", "detail": "The AI is not set up yet (GROQ_API_KEY is missing)."}
        return

    answer = ""
    for piece in stream_llm(build_messages(SYSTEM_PROMPT, question, retrieved, history)):
        answer += piece
        yield {"type": "answer", "delta": piece}

    # The technical explanation only makes sense when real graph records were found
    graph_facts = retrieved["mode"] in ("id_lookup", "hybrid_vector") and retrieved["facts"]
    details = ""
    if explain and graph_facts and not answer.startswith(REFUSAL):
        for piece in stream_llm(build_messages(DETAILS_PROMPT, question, retrieved)):
            details += piece
            yield {"type": "details", "delta": piece}

    yield {"type": "done", "grounding": grounding_check(answer + " " + details, retrieved)}


def answer(question, history=(), explain=True):
    """The same answer as one dictionary, for code that doesn't need streaming (the /ask route, the tests)."""
    result = {"question": question, "answer": "", "details": ""}
    for event in answer_stream(question, history, explain):
        if event["type"] in ("answer", "details"):
            result[event["type"]] += event["delta"]
        elif event["type"] == "error":
            raise RuntimeError(event["detail"])
        else:
            result.update({key: value for key, value in event.items() if key != "type"})
    return result
