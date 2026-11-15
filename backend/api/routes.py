"""The API the website calls. Each function below is one URL."""
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from graph import queries
from graph.connection import driver, run
from rag.pipeline import answer, answer_stream

router = APIRouter()


class Question(BaseModel):
    """What the website sends: the question, plus earlier turns of the chat for follow-ups."""
    question: str
    history: list[dict] = Field(default_factory=list)  # [{"question": ..., "answer": ...}, ...]


@router.get("/health")
def health():
    """Is the database reachable, and how many nodes does it hold?"""
    try:
        driver.verify_connectivity()
        nodes = run("MATCH (n) RETURN count(n) AS n")[0]["n"]
        return {"status": "ok", "neo4j": "connected", "nodes": nodes}
    except Exception as exc:
        raise HTTPException(503, f"Neo4j unavailable: {exc}")


@router.get("/cve/{cve_id}")
def cve(cve_id: str):
    """The raw graph record of one CVE, e.g. /cve/CVE-2024-24919."""
    rows = run(queries.CVE_CHAIN, id=cve_id.upper())
    if not rows or rows[0]["cve"] is None:
        raise HTTPException(404, f"{cve_id} not found")
    return rows[0]


@router.post("/ask")
def ask(body: Question):
    """The whole answer at once, as one JSON object."""
    if not body.question.strip():
        raise HTTPException(400, "question is empty")
    try:
        return answer(body.question.strip(), body.history)
    except Exception as exc:
        raise HTTPException(500, f"API error: {exc}") from exc


@router.post("/ask/stream")
def ask_stream(body: Question):
    """The answer while it is being written: one JSON event per line, so the website can type it out."""
    if not body.question.strip():
        raise HTTPException(400, "question is empty")

    def lines():
        try:
            for event in answer_stream(body.question.strip(), body.history):
                yield json.dumps(event, default=str) + "\n"
        except Exception as exc:  # e.g. the AI's daily limit is used up
            yield json.dumps({"type": "error", "detail": f"The AI could not answer: {exc}"}) + "\n"

    return StreamingResponse(lines(), media_type="application/x-ndjson")
