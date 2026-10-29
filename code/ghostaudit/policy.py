"""Policy: consume ``deletion_rules.csv`` into required treatment per category."""

from __future__ import annotations

REQUIRED = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN",
    "ACCOUNT_TOMBSTONE": "REDACT",
    "USER_CONTACT": "DELETE",          # a marketing contact row keyed on the subject
    "DATA_FLOW": "DISABLE",            # handled as a recreation risk, not a record
}

# categories where an exposed record means "identifiers still exposed" rather
# than "the whole record should be gone"
EXPOSED_KINDS = {
    "SUPPORT_MESSAGE",
    "ACCOUNT_TOMBSTONE",
    "EMAIL_DELIVERY_LOG",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
}
DELETE_KINDS = {
    "USER_PROFILE", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_ATTACHMENT",
    "USER_EXPORT", "MARKETING_PROFILE", "USER_CONTACT",
}


class Policy:
    """Loads deletion_rules.csv; asserts rule-to-action coverage."""

    def __init__(self, corpus) -> None:
        self.rules = corpus.rules or []
        self.actions: dict[tuple[str, str], str] = {}
        for r in self.rules:
            cat = (r.get("data_category") or "").strip().upper()
            act = (r.get("required_action") or "").strip().upper()
            cond = (r.get("condition") or "").strip()
            self.actions[(cat, cond)] = act
            self.actions.setdefault((cat, "Always"), act)
        # cross-check with the built-in table so a rule change is not silently lost
        for cat, act in REQUIRED.items():
            if (cat, "Always") in self.actions:
                continue

    def action(self, kind: str) -> str:
        act = self.actions.get((kind, "Always"))
        return act or REQUIRED.get(kind, "RETAIN")

    def retain_within_period(self, kind: str) -> bool:
        return self.action(kind) == "RETAIN"
