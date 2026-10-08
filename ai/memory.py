"""Atomic, per-session local memory and conversation persistence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
from uuid import UUID

from .schemas import DEFAULT_PROFILE

_LOCK = threading.RLock()


def owner_key(owner: str) -> str:
    return hashlib.sha256(owner.encode("utf-8")).hexdigest()


def signing_key(root: Path) -> bytes:
    path = root / "owner_signing_key"
    with _LOCK:
        try:
            value = path.read_bytes()
            if len(value) >= 32:
                return value
        except OSError:
            pass
        value = secrets.token_bytes(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(value)
        os.replace(temporary, path)
        return value


def _read(path: Path, default):
    try:
        with path.open("r", encoding="utf-8") as memory_file:
            value = json.load(memory_file)
        return value if isinstance(value, dict) else default
    except (OSError, json.JSONDecodeError):
        return default


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as memory_file:
        json.dump(value, memory_file, ensure_ascii=True, indent=2)
    os.replace(temporary, path)


def memory_path(root: Path, owner: str) -> Path:
    return root / "memory" / f"{owner_key(owner)}.json"


def conversation_dir(root: Path, owner: str) -> Path:
    return root / "conversations" / owner_key(owner)


def conversation_path(root: Path, owner: str, conversation_id: str) -> Path:
    try:
        normalized = str(UUID(conversation_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid conversation ID.") from exc
    return conversation_dir(root, owner) / f"{normalized}.json"


def default_memory() -> dict:
    return {
        "enabled": True,
        "profile": dict(DEFAULT_PROFILE),
        "explicit_memories": [],
        "learning": {"topics_covered": [], "topics_to_review": [], "quiz_results": []},
        "remediation": {},
        "pending_quizzes": {},
    }


def load_memory(root: Path, owner: str) -> dict:
    with _LOCK:
        value = _read(memory_path(root, owner), default_memory())
    result = default_memory()
    result.update(value)
    if not isinstance(result.get("profile"), dict):
        result["profile"] = dict(DEFAULT_PROFILE)
    if not isinstance(result.get("learning"), dict):
        result["learning"] = default_memory()["learning"]
    for key, fallback in (("explicit_memories", []), ("remediation", {}), ("pending_quizzes", {})):
        if not isinstance(result.get(key), type(fallback)):
            result[key] = fallback
    return result


def save_memory(root: Path, owner: str, value: dict) -> None:
    with _LOCK:
        _write(memory_path(root, owner), value)


def load_conversation(root: Path, owner: str, conversation_id: str | None) -> dict | None:
    if not conversation_id:
        return None
    path = conversation_path(root, owner, conversation_id)
    with _LOCK:
        value = _read(path, None)
    if not isinstance(value, dict):
        return None
    value.pop("active_mode", None)
    value.pop("module_mode", None)
    return value


def save_conversation(root: Path, owner: str, conversation: dict) -> None:
    path = conversation_path(root, owner, conversation["conversation_id"])
    with _LOCK:
        _write(path, conversation)


def clear_conversation(root: Path, owner: str, conversation_id: str) -> bool:
    path = conversation_path(root, owner, conversation_id)
    with _LOCK:
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False


def clear_learning(root: Path, owner: str) -> None:
    value = load_memory(root, owner)
    value["learning"] = default_memory()["learning"]
    value["pending_quizzes"] = {}
    save_memory(root, owner, value)


def clear_all(root: Path, owner: str) -> None:
    key = owner_key(owner)
    with _LOCK:
        path = memory_path(root, owner)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        directory = root / "conversations" / key
        if directory.is_dir():
            for item in directory.glob("*.json"):
                item.unlink(missing_ok=True)
            directory.rmdir()