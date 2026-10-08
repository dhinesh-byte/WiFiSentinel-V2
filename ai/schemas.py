"""Shared schemas and validation limits for VulnScan AI."""

MAX_MESSAGE_CHARS = 4000
MAX_REQUEST_BYTES = 16384
MAX_CONVERSATION_MESSAGES = 30
MAX_CONTEXT_CHARS = 14000

ASSESSMENT_MODULES = frozenset({"defensive", "offensive"})
REMEDIATION_STATUSES = frozenset({
    "DETECTED",
    "ANALYZING",
    "REMEDIATION_READY",
    "ACTION_REQUIRED",
    "VERIFICATION_RUNNING",
    "STILL_PRESENT",
    "INCONCLUSIVE",
    "CANCELLED",
    "OPEN",
    "INVESTIGATING",
    "REMEDIATION_RECOMMENDED",
    "RESCAN_REQUIRED",
    "VERIFIED",
    "ACCEPTED_RISK",
})

DEFAULT_PROFILE = {
    "knowledge_level": "BEGINNER",
    "explanation_style": "BALANCED",
    "preferred_language": "ENGLISH",
}


def normalize_profile(value):
    """Return a valid learning profile, falling back field-by-field."""
    if not isinstance(value, dict):
        value = {}
    allowed = {
        "knowledge_level": {"BEGINNER", "INTERMEDIATE", "ADVANCED"},
        "explanation_style": {"SIMPLE", "BALANCED", "TECHNICAL"},
        "preferred_language": {"ENGLISH", "SPANISH", "FRENCH", "HINDI", "ARABIC"},
    }
    profile = {}
    for field, choices in allowed.items():
        candidate = value.get(field, DEFAULT_PROFILE[field])
        candidate = candidate.upper() if isinstance(candidate, str) else ""
        profile[field] = candidate if candidate in choices else DEFAULT_PROFILE[field]
    return profile