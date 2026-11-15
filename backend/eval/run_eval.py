"""Score GraphRAG against the same LLM with no graph, on data/eval/benchmark.json.

Run from backend/:  python -m eval.run_eval [max_questions]
Writes data/eval/results.json and a copy for the web app's Research page.

Both systems use the same model, so any difference comes from the graph:
  graphrag   our pipeline: Neo4j facts + the answer prompt
  plain_llm  the model alone, asked the same question
"""
import json
import re
import statistics
import sys
import time
from pathlib import Path

from eval import tls  # noqa: F401
from groq import Groq

import config
from rag import pipeline
from rag.grounding import ID, normalize

ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "data" / "eval" / "benchmark.json"
OUTPUTS = [ROOT / "data" / "eval" / "results.json", ROOT / "frontend" / "data" / "eval-results.json"]

PLAIN_PROMPT = """You are a cybersecurity expert. Answer the question in 1 to 3 short sentences.
Include the exact IDs (CVE, CWE, CAPEC, ATT&CK) and numbers you are asked for."""

# Which ID family a question asks for, so only those IDs count toward precision and recall
TARGET = {"cve_to_cwe": "CWE-", "cwe_to_capec": "CAPEC-", "capec_to_attack": "T"}


def ask_plain(question):
    client = Groq(api_key=config.GROQ_API_KEY, max_retries=0)  # with_retry waits, so latency stays clean
    reasoning = ({"reasoning_effort": config.GROQ_REASONING_EFFORT, "include_reasoning": False}
                 if config.GROQ_REASONING_EFFORT else {})
    response = client.chat.completions.create(
        model=config.GROQ_MODEL, temperature=0.1, **reasoning,
        messages=[{"role": "system", "content": PLAIN_PROMPT}, {"role": "user", "content": question}])
    return (response.choices[0].message.content or "").strip()


def ask_graphrag(question):
    return pipeline.answer(question, explain=False)["answer"]


def with_retry(fn, question):
    """Groq's free tier rate-limits; wait and retry instead of failing the run."""
    for attempt in range(6):
        try:
            start = time.perf_counter()
            text = fn(question)
            return text, round(time.perf_counter() - start, 2)
        except Exception as exc:
            if "429" not in str(exc) and "rate" not in str(exc).lower():
                return f"[error] {exc}", None
            time.sleep(10 * (attempt + 1))
    return "[error] rate limited", None


def score(item, text):
    """Returns accuracy (0..1), precision, recall and the IDs the answer invented."""
    kind, truth = item["type"], item["truth"]
    text = normalize(text)
    if kind == "severity":
        ok_sev = truth["severity"].lower() in text.lower()
        ok_score = re.search(rf"(?<![\d.]){re.escape(str(truth['base_score']))}(?![\d])", text) is not None
        return {"accuracy": (ok_sev + ok_score) / 2, "precision": None, "recall": None, "invented": []}
    if kind == "cve_count":
        numbers = {int(n) for n in re.findall(r"(?<![\w.-])(\d{1,6})(?![\w.])", text.replace(",", ""))}
        return {"accuracy": float(truth in numbers), "precision": None, "recall": None, "invented": []}
    prefix = TARGET[kind]
    said = {m.upper() for m in ID.findall(text)}
    said = {i for i in said if i.startswith(prefix) and not (prefix == "T" and i.startswith("CVE"))}
    want = set(truth)
    hits = said & want
    precision = len(hits) / len(said) if said else 0.0
    recall = len(hits) / len(want)
    f1 = 2 * precision * recall / (precision + recall) if hits else 0.0
    return {"accuracy": f1, "precision": precision, "recall": recall, "invented": sorted(said - want)}


def summarize(rows, system):
    mine = [r[system] for r in rows]
    by_type = {}
    for r in rows:
        by_type.setdefault(r["type"], []).append(r[system]["accuracy"])
    claimed = sum(len(r[system]["said"]) for r in rows if r["type"] in TARGET)
    invented = sum(len(r[system]["invented"]) for r in rows)
    latencies = [m["latency"] for m in mine if m["latency"] is not None]
    return {
        "accuracy": round(statistics.mean(m["accuracy"] for m in mine), 3),
        "by_type": {k: round(statistics.mean(v), 3) for k, v in by_type.items()},
        # Share of the IDs an answer named that are not real links for that entity
        "hallucination_rate": round(invented / claimed, 3) if claimed else 0.0,
        "median_latency_s": round(statistics.median(latencies), 2) if latencies else None,
        "errors": sum(1 for m in mine if m["text"].startswith("[error]")),
    }


def judge(item, text, latency):
    result = score(item, text)
    said = sorted({m.upper() for m in ID.findall(normalize(text))}) if item["type"] in TARGET else []
    return {"text": text, "latency": latency, "said": said, **result}


def main(limit=None, rescore=False):
    if rescore:  # re-mark saved answers after a scoring fix, without calling the model again
        old = json.loads(OUTPUTS[0].read_text(encoding="utf-8"))
        rows = old["rows"]
        for row in rows:
            for system in ("graphrag", "plain_llm"):
                row[system] = judge(row, row[system]["text"], row[system]["latency"])
        meta = {k: old[k] for k in ("model", "reasoning_effort", "run_at")}
    else:
        items = json.loads(BENCHMARK.read_text(encoding="utf-8"))[:limit]
        rows = []
        for n, item in enumerate(items, 1):
            row = {k: item[k] for k in ("id", "type", "entity", "question", "truth")}
            for system, fn in (("graphrag", ask_graphrag), ("plain_llm", ask_plain)):
                row[system] = judge(item, *with_retry(fn, item["question"]))
            rows.append(row)
            print(f"[{n}/{len(items)}] {item['type']:<16} rag={row['graphrag']['accuracy']:.2f} "
                  f"plain={row['plain_llm']['accuracy']:.2f}", flush=True)
        meta = {"model": config.GROQ_MODEL, "reasoning_effort": config.GROQ_REASONING_EFFORT,
                "run_at": time.strftime("%Y-%m-%d %H:%M")}

    report = {
        **meta,
        "questions": len(rows),
        "summary": {s: summarize(rows, s) for s in ("graphrag", "plain_llm")},
        "rows": rows,
    }
    for path in OUTPUTS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--rescore"]
    main(int(args[0]) if args else None, rescore="--rescore" in sys.argv)
