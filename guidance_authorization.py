"""Short-lived, in-memory authorization tokens for vulnerability learning."""

from __future__ import annotations

import secrets
import threading
import time

_TOKEN_TTL_SECONDS = 30 * 60
_MAX_TOKENS = 1000
_LOCK = threading.Lock()
_TOKENS: dict[str, tuple[str, str, float]] = {}


def issue_guidance_token(report_id: str, finding_id: str) -> str:
	"""Issue a short-lived token scoped to one report and finding."""
	now = time.monotonic()
	with _LOCK:
		expired = [token for token, (_, _, expires) in _TOKENS.items() if expires <= now]
		for token in expired:
			del _TOKENS[token]
		if len(_TOKENS) >= _MAX_TOKENS:
			oldest = min(_TOKENS, key=lambda token: _TOKENS[token][2])
			del _TOKENS[oldest]
		token = secrets.token_urlsafe(32)
		_TOKENS[token] = (report_id, finding_id, now + _TOKEN_TTL_SECONDS)
		return token


def guidance_token_is_valid(token: object, report_id: str, finding_id: str) -> bool:
	"""Check that a current token authorizes only the matching finding."""
	if not isinstance(token, str) or not token:
		return False
	now = time.monotonic()
	with _LOCK:
		record = _TOKENS.get(token)
		if record is None:
			return False
		if record[2] <= now:
			del _TOKENS[token]
			return False
		return record[:2] == (report_id, finding_id)
