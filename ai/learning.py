"""Original, bounded cybersecurity quiz content and progress tracking."""

from __future__ import annotations

from uuid import uuid4

from .knowledge import LEARNING_PATHS

QUIZZES = [
    {"topic": "Ports", "difficulty": "BEGINNER", "question": "Which transport protocol is commonly associated with TCP port 443?", "options": {"a": "HTTPS", "b": "SSH", "c": "DNS"}, "answer": "a", "explanation": "TCP/443 is commonly used for HTTPS. A port number is an association, not proof of which application is running."},
    {"topic": "Networking", "difficulty": "BEGINNER", "question": "What does a TCP port identify on a host?", "options": {"a": "A specific network service endpoint", "b": "The host's physical location", "c": "A Wi-Fi password"}, "answer": "a", "explanation": "A port helps identify a service endpoint within a transport protocol on a host."},
    {"topic": "DNS", "difficulty": "INTERMEDIATE", "question": "What does a DNS A record normally map?", "options": {"a": "A hostname to an IPv4 address", "b": "A certificate to a cipher", "c": "A TCP port to a process"}, "answer": "a", "explanation": "An A record maps a DNS name to an IPv4 address. Other record types serve different purposes."},
    {"topic": "TLS", "difficulty": "INTERMEDIATE", "question": "What does a successful TLS handshake establish by itself?", "options": {"a": "That the application has no vulnerabilities", "b": "That a TLS connection was negotiated", "c": "That the user is authorized"}, "answer": "b", "explanation": "A handshake establishes cryptographic connection parameters. It does not prove the application is secure or the user is authorized."},
    {"topic": "Service enumeration", "difficulty": "ADVANCED", "question": "Why should an identified product/version be treated as evidence rather than proof of vulnerability?", "options": {"a": "Fingerprinting can be uncertain and vulnerability applicability needs validation", "b": "Versions never matter", "c": "Every service banner proves exploitation"}, "answer": "a", "explanation": "Service fingerprints can be incomplete or inaccurate, and applicability depends on conditions such as exact build, configuration, and vendor backports."},
    {"topic": "Segmentation", "difficulty": "ADVANCED", "question": "Which observation best verifies that a firewall change reduced exposure?", "options": {"a": "A later authorized scan from the relevant vantage point no longer observes the service", "b": "A configuration was saved", "c": "A host has a high risk score"}, "answer": "a", "explanation": "A later scan from an appropriate vantage point provides evidence about observed reachability. It still does not prove every path is blocked."},
]


def start_quiz(memory: dict, topic: str | None, difficulty: str | None) -> dict:
    normalized_difficulty = (difficulty or "BEGINNER").upper()
    if normalized_difficulty not in {"BEGINNER", "INTERMEDIATE", "ADVANCED"}:
        raise ValueError("Difficulty must be BEGINNER, INTERMEDIATE, or ADVANCED.")
    candidates = [item for item in QUIZZES if item["difficulty"] == normalized_difficulty]
    if topic:
        matching = [item for item in candidates if topic.lower() in item["topic"].lower()]
        if matching:
            candidates = matching
    question = candidates[0]
    quiz_id = str(uuid4())
    pending = memory.setdefault("pending_quizzes", {})
    pending[quiz_id] = question
    while len(pending) > 10:
        pending.pop(next(iter(pending)))
    return {"quiz_id": quiz_id, "topic": question["topic"], "difficulty": question["difficulty"], "question": question["question"], "options": question["options"]}


def answer_quiz(memory: dict, quiz_id: str, answer: str) -> dict:
    question = memory.setdefault("pending_quizzes", {}).pop(quiz_id, None)
    if not isinstance(question, dict):
        raise ValueError("Quiz question was not found or has already been answered.")
    normalized = answer.strip().lower()
    correct = normalized == question["answer"] or normalized == question["options"][question["answer"]].lower()
    learning = memory.setdefault("learning", {"topics_covered": [], "topics_to_review": [], "quiz_results": []})
    if question["topic"] not in learning.setdefault("topics_covered", []):
        learning["topics_covered"].append(question["topic"])
    if not correct and question["topic"] not in learning.setdefault("topics_to_review", []):
        learning["topics_to_review"].append(question["topic"])
    learning["quiz_results"].append({"topic": question["topic"], "difficulty": question["difficulty"], "correct": correct})
    learning["quiz_results"] = learning["quiz_results"][-50:]
    return {"correct": correct, "correct_answer": question["options"][question["answer"]], "explanation": question["explanation"], "topic": question["topic"]}


def learning_paths(memory: dict) -> list[dict]:
    covered = set(memory.get("learning", {}).get("topics_covered", []))
    results = []
    for path in LEARNING_PATHS:
        statuses = [
            {"name": concept, "status": "covered" if concept in covered else "not_started"}
            for concept in path["concepts"]
        ]
        results.append({
            **path,
            "concept_status": statuses,
            "next_concept": next((item["name"] for item in statuses if item["status"] == "not_started"), None),
        })
    return results