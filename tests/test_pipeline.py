"""Three checks: IDs are found, vague questions use search by meaning, off-topic questions are refused."""
import pytest

import config
from api.routes import Question
from rag import embeddings
from rag.pipeline import answer, find_ids, is_follow_up, retrieve
from rag.prompts import REFUSAL


def test_finds_ids_in_any_form():
    assert find_ids("Is CVE-2024-24919 bad?") == ["CVE-2024-24919"]
    assert find_ids("what is cwe 89 and CAPEC 66") == ["CWE-89", "CAPEC-66"]
    assert find_ids("T1574.008 and t1036") == ["T1574.008", "T1036"]
    assert find_ids("how do attackers steal login sessions?") == []


def test_id_question_uses_id_lookup():
    result = retrieve("Which ATT&CK techniques are reachable from CVE-2024-24919?")
    assert result["mode"] == "id_lookup"
    assert result["facts"][0]["cve"]["id"] == "CVE-2024-24919"


def test_only_real_follow_ups_reuse_earlier_ids():
    assert is_follow_up("how do I fix it?")
    assert not is_follow_up("how do attackers steal login sessions?")
    earlier = [{"question": "What is CVE-2024-24919?", "answer": "High severity."}]
    assert retrieve("how do I fix it?", earlier)["ids"] == ["CVE-2024-24919"]
    assert retrieve("Who won the 2023 cricket World Cup?", earlier)["mode"] != "id_lookup"


def test_question_history_is_not_shared_between_requests():
    first = Question(question="What is CVE-2024-24919?")
    second = Question(question="How do I patch it?")

    first.history.append({"question": "What is this?", "answer": "Answer"})

    assert first.history == [{"question": "What is this?", "answer": "Answer"}]
    assert second.history == []


@pytest.mark.skipif(not embeddings.available(), reason="embedding model not installed")
def test_vague_question_uses_hybrid_search():
    result = retrieve("how do attackers steal login sessions?")
    assert result["mode"] == "hybrid_vector"
    entries = [fact["entry"] for fact in result["facts"]]
    assert entries and all(e["score"] >= config.VECTOR_MIN_SCORE for e in entries)
    assert all("paths" in fact or "capecs" in fact or "cwes" in fact for fact in result["facts"])


@pytest.mark.skipif(not config.GROQ_API_KEY, reason="no GROQ_API_KEY")
def test_off_topic_question_is_refused():
    result = answer("Who won the 2023 cricket World Cup?", explain=False)
    assert result["answer"].startswith(REFUSAL)
