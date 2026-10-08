"""Conversation context management and bounded history summaries."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .schemas import MAX_CONVERSATION_MESSAGES


def new_conversation(module: str, scan_id=None, host_id=None, finding_id=None) -> dict:
    return {
        "conversation_id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "module": module,
        "selected_scan": scan_id,
        "selected_host": host_id,
        "selected_finding": finding_id,
        "summary": "",
        "messages": [],
    }


def _normalized_message(value: str) -> str:
    return " ".join(str(value or "").split()).lower()


def append_exchange(conversation: dict, module: str, scan_id, host_id, finding_id, user_text: str, answer: str) -> None:
    messages = conversation.get("messages", [])
    if not isinstance(messages, list):
        messages = []

    user_message = {"role": "user", "content": user_text, "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    assistant_message = {"role": "assistant", "content": answer, "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    if len(messages) >= 2:
        previous_user = messages[-2]
        previous_assistant = messages[-1]
        if (
            isinstance(previous_user, dict)
            and previous_user.get("role") == "user"
            and isinstance(previous_assistant, dict)
            and previous_assistant.get("role") == "assistant"
            and _normalized_message(previous_user.get("content", "")) == _normalized_message(user_text)
            and _normalized_message(previous_assistant.get("content", "")) == _normalized_message(answer)
        ):
            return

    messages.extend((user_message, assistant_message))
    if len(messages) > MAX_CONVERSATION_MESSAGES or (conversation.get("summary") and len(messages) > 12):
        older = messages[:-12]
        snippets = [f"{item.get('role', 'user')}: {str(item.get('content', ''))[:180]}" for item in older[-8:]]
        conversation["summary"] = "Earlier conversation topics (summary, not scanner evidence): " + " | ".join(snippets)[:1200]
        messages = messages[-12:]
    conversation.update({
        "module": module,
        "selected_scan": scan_id,
        "selected_host": host_id,
        "selected_finding": finding_id,
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "messages": messages,
    })


def provider_history(conversation: dict) -> list[dict[str, str]]:
    result = []
    summary = conversation.get("summary")
    if isinstance(summary, str) and summary:
        result.append({"role": "assistant", "content": summary})
    for item in conversation.get("messages", [])[-12:]:
        if isinstance(item, dict) and item.get("role") in {"user", "assistant"} and isinstance(item.get("content"), str):
            result.append({"role": item["role"], "content": item["content"][:4000]})
    return result