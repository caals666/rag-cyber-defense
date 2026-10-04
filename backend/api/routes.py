from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from graph import queries
from graph.connection import driver, run
from rag.pipeline import answer

router = APIRouter()


class Question(BaseModel):
    question: str


@router.get("/health")
def health():
    try:
        driver.verify_connectivity()
        nodes = run("MATCH (n) RETURN count(n) AS n")[0]["n"]
        return {"status": "ok", "neo4j": "connected", "nodes": nodes}
    except Exception as exc:
        raise HTTPException(503, f"Neo4j unavailable: {exc}")


@router.get("/cve/{cve_id}")
def cve(cve_id: str):
    rows = run(queries.CVE_CHAIN, id=cve_id.upper())
    if not rows or rows[0]["cve"] is None:
        raise HTTPException(404, f"{cve_id} not found")
    return rows[0]


@router.post("/ask")
def ask(body: Question):
    if not body.question.strip():
        raise HTTPException(400, "question is empty")
    try:
        return answer(body.question.strip())
    except Exception as exc:
        raise HTTPException(500, f"API error: {exc}") from exc
