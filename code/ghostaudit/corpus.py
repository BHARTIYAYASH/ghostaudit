"""Identity graph: current snapshot + historical audit-log values.

Builds, for every ``user_id`` in ``user_identities.csv``, the full set of
identifiers that older systems may still hold:

* current email / phone / email_hash
* historical values seen in ``user_audit_log.csv`` (old + new values, with times)
* the stable internal subject reference (``user_NN``)
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field


def _norm_email(v: str | None) -> str:
    return (v or "").strip().lower()


def _norm_phone(v: str | None) -> str:
    """Normalize a phone number to digits only, keeping leading +."""
    if not v:
        return ""
    digits = "".join(ch for ch in v if ch.isdigit())
    return digits


@dataclass
class Identity:
    user_id: str
    name: str = ""
    emails: set[str] = field(default_factory=set)          # current + historical, lowercased
    phones: set[str] = field(default_factory=set)          # normalized digits
    hashes: set[str] = field(default_factory=set)          # email hashes, lowercased
    user_ids: set[str] = field(default_factory=set)        # the stable reference, e.g. {"user_04"}
    # email -> ("current" | audit timestamp of the last event touching it)
    email_history: dict[str, str] = field(default_factory=dict)

    def identifiers(self) -> set[str]:
        """Lowercased identifier pool used for exact-match binding."""
        out: set[str] = set()
        out |= self.emails
        out |= {("p:" + p) for p in self.phones if p}
        out |= self.hashes
        out |= self.user_ids
        return out


class Corpus:
    """Loads all input CSVs and builds the identity graph."""

    def __init__(self, dataset_dir: str) -> None:
        self.dataset_dir = dataset_dir
        self.requests = self._rows("deletion_requests.csv")
        self.samples = self._rows("sample_deletion_requests.csv")
        self.sample_output = self._rows("sample_output.csv")
        self.identities = self._rows("user_identities.csv")
        self.audit_log = self._rows("user_audit_log.csv")
        self.activity = self._rows("system_activity.csv")
        self.rules = self._rows("deletion_rules.csv")
        self.manifest = self._rows("evidence_files.csv")

        self.user_by_email: dict[str, Identity] = {}
        self.email_to_users: dict[str, list[Identity]] = {}
        self.identities_by_uid: dict[str, Identity] = {}
        self._build_identity_graph()

    # ------------------------------------------------------------------ utils
    def _rows(self, name: str) -> list[dict]:
        path = os.path.join(self.dataset_dir, name)
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            return [dict(r) for r in csv.DictReader(fh)]

    # ------------------------------------------------------------- identities
    def _build_identity_graph(self) -> None:
        for row in self.identities:
            uid = row["user_id"]
            ident = Identity(user_id=uid, name=(row.get("name") or "").strip())
            ident.user_ids.add(uid)
            email = _norm_email(row.get("email"))
            if email:
                ident.emails.add(email)
                ident.email_history[email] = row.get("updated_at", "")
            phone = _norm_phone(row.get("phone"))
            if phone:
                ident.phones.add(phone)
            h = _norm_email(row.get("email_hash"))
            if h:
                ident.hashes.add(h)
            self.identities_by_uid[uid] = ident

        # merge historical values from the audit trail
        for ev in self.audit_log:
            uid = ev["user_id"]
            ident = self.identities_by_uid.get(uid)
            if ident is None:
                ident = Identity(user_id=uid)
                ident.user_ids.add(uid)
                self.identities_by_uid[uid] = ident
            fname = ev.get("field_name", "")
            t = ev.get("event_time", "")
            for value in (ev.get("old_value"), ev.get("new_value")):
                value = _norm_email(value)
                if not value:
                    continue
                if fname == "email":
                    ident.emails.add(value)
                    ident.email_history[value] = t
                elif fname == "email_hash":
                    ident.hashes.add(value)
                elif fname == "phone":
                    ident.phones.add(value)
            if fname == "email":
                # both sides of the change belong to the same person at
                # consecutive points in time
                old, new = _norm_email(ev.get("old_value")), _norm_email(ev.get("new_value"))
                for e in (old, new):
                    if e:
                        ident.email_history[e] = t

        # email -> user index
        for uid, ident in self.identities_by_uid.items():
            for e in ident.emails:
                self.email_to_users.setdefault(e, []).append(ident)
                self.user_by_email.setdefault(e, ident)

    # ------------------------------------------------------------ resolution
    def resolve_user(self, email: str) -> Identity | None:
        """Resolve a request email to an identity (current or historical)."""
        e = _norm_email(email)
        hits = self.email_to_users.get(e)
        if not hits:
            return None
        if len(hits) == 1:
            return hits[0]
        # prefer the identity for which the email is *current*, then the most
        # recent audit event mentioning it
        for ident in hits:
            cur = None
            for row in self.identities:
                if row["user_id"] == ident.user_id and _norm_email(row.get("email")) == e:
                    cur = ident
                    break
            if cur is not None:
                return cur
        latest, latest_i = None, ""
        for ident in hits:
            t = ident.email_history.get(e, "")
            if t > latest_i:
                latest, latest_i = ident, t
        return latest or hits[0]

    def new_identity_for_audit(self, uid: str) -> Identity:
        return self.identities_by_uid.get(uid) or Identity(user_id=uid)

    # ------------------------------------------------------------ file paths
    def evidence_path(self, file_path: str) -> str:
        return os.path.join(self.dataset_dir, file_path.replace("/", os.sep))
