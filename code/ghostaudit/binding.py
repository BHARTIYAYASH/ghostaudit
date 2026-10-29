"""Binding: connect subject identities to resources via every grounded channel.

All attribution channels may use ANY evidence file regardless of its capture
time (identity attribution is timeless); only *state determination* and
citations are later gated per case by ``obs.t <= audit_at`` together with
``file.captured_at <= audit_at`` (see pipeline).

Channels:

* exact raw-identifier match inside an evidence observation (current or
  historical email, phone, email hash, stable ``user_NN`` reference);
* explicit data-catalog links (``LINK_RESOURCE_IDENTITY`` activities);
* workflow-op band correlation for the account (the DELETE_RECORD band around
  the workflow report) with result-pattern preference, claim exclusions and a
  deterministic cross-case zip for shared pools;
* analytics pairing within a reported-at cluster;
* audit-record pick from the latest captured file that binds the subject.

Decoys (perturbed lookalikes such as "Mateo Rios Gil" / ``m.rios.gil@..`` and
``user_9116``) are rejected because name similarity is never a binding signal
and identifiers must match exactly; raw identifier strings that belong to no
registered identity (e.g. ``SIPHO.MOKOENA@GMAIL.COM``) still claim resources
away from every other subject.
"""

from __future__ import annotations

import re
from datetime import timedelta

from .activity import WORKFLOW_SOURCE
from .parse_evidence import Observation, _dt, subjects_from_text


def _acct_from_user(user_id: str) -> str | None:
    m = re.fullmatch(r"user_(\d+)", user_id or "")
    if not m:
        return None
    return "account_" + m.group(1).zfill(3)


def identity_tokens(ident) -> set[str]:
    """The full identifier pool of an identity (current + historical)."""
    toks: set[str] = set()
    toks |= {(e.strip().lower()) for e in (ident.emails or set()) if e}
    toks |= {("p:" + "".join(ch for ch in p if ch.isdigit())) for p in (ident.phones or set()) if p}
    toks |= {(h.strip().lower()) for h in (ident.hashes or set()) if h}
    toks |= {u.strip().lower() for u in (ident.user_ids or set()) if u}
    toks.discard("")
    return toks


class ResourceMap:
    """All observations / ops for one resource id."""

    def __init__(self) -> None:
        self.observations: list[Observation] = []
        self.ops: list = []
        self.users: dict[str, set[str]] = {}   # user_id -> channels that bound it
        self.tokens: set[str] = set()          # raw identifier tokens from evidence

    def add_user(self, user_id: str, channel: str) -> None:
        self.users.setdefault(user_id, set()).add(channel)

    @property
    def system(self) -> str:
        for o in self.observations:
            if o.system:
                return o.system
        for o in self.ops:
            if o.target_system:
                return o.target_system
        return ""


class BindingIndex:
    def __init__(self, corpus, observations: list[Observation], activity) -> None:
        self.corpus = corpus
        self.activity = activity
        self.resources: dict[str, ResourceMap] = {}
        # token -> user_ids resolution cache (needed during indexing)
        self._tok_users: dict[str, set[str]] = {}
        self._index_resources(observations)
        self._index_activity()

    # ------------------------------------------------------------- indexing
    def _index_resources(self, observations) -> None:
        for obs in observations:
            rm = self.resources.setdefault(obs.resource_id, ResourceMap())
            rm.observations.append(obs)
            toks = {t for t in (obs.subjects or set()) if t}
            rm.tokens |= toks
            for uid in self.token_users(toks):
                rm.add_user(uid, "id")
        for ln in self.activity.links:
            rm = self.resources.setdefault(ln.resource_id, ResourceMap())
            rm.ops.append(ln)
            toks = {t for t in (ln.subjects or set()) if t}
            rm.tokens |= toks
            for uid in self.token_users(toks):
                rm.add_user(uid, "link")

    def _index_activity(self) -> None:
        for op in self.activity.ops:
            rm = self.resources.setdefault(op.resource_id, ResourceMap())
            rm.ops.append(op)
            for uid in self.token_users(op.subjects or set()):
                rm.add_user(uid, "op")

    def token_users(self, tokens) -> set[str]:
        """Identifier tokens -> user_ids (registry-based resolution)."""
        out: set[str] = set()
        for tok in tokens or ():
            cache = self._tok_users.get(tok)
            if cache is not None:
                out |= cache
                continue
            users: set[str] = set()
            if tok.startswith("user_") and re.fullmatch(r"user_\d+", tok):
                users.add(tok)
            elif tok.startswith("p:"):
                phone = tok[2:]
                if phone:
                    for uid, ident in self.corpus.identities_by_uid.items():
                        if phone in ident.phones:
                            users.add(uid)
            elif re.fullmatch(r"[0-9a-f]{64}", tok):
                for uid, ident in self.corpus.identities_by_uid.items():
                    if tok in ident.hashes:
                        users.add(uid)
            elif "@" in tok:
                for ident in self.corpus.email_to_users.get(tok, []):
                    users.add(ident.user_id)
            self._tok_users[tok] = users
            out |= users
        return out

    # ---------------------------------------------------------- queries
    def evidence_users(self, rid: str) -> set[str]:
        rm = self.resources.get(rid)
        if not rm:
            return set()
        return {u for u, chs in rm.users.items() if chs & {"id", "link"}}

    def user_resources(self, uid: str, ident=None) -> dict[str, list[str]]:
        """Resources bound to the user by evidence identifiers/links."""
        out: dict[str, list[str]] = {}
        toks = identity_tokens(ident) if ident is not None else None
        for rid, rm in self.resources.items():
            if toks is not None:
                if rm.tokens & toks:
                    out.setdefault(kind_of_resource(rid, rm), []).append(rid)
            elif uid in self.evidence_users(rid):
                out.setdefault(kind_of_resource(rid, rm), []).append(rid)
        return out

    # ------------------------------------------------------- state helpers
    def resources_with_kind(self, kind: str) -> list[str]:
        return [rid for rid, rm in self.resources.items()
                if (kind_of_resource(rid, rm) == kind)]

    def latest_audit_record(self, ident) -> str | None:
        """Account audit-record binding: latest captured file binding the user."""
        toks = identity_tokens(ident)
        best = None
        for rid, rm in self.resources.items():
            if not rid.startswith("audit_record"):
                continue
            if not (rm.tokens & toks):
                continue
            for obs in rm.observations:
                key = (_dt(obs.captured_at or obs.t), obs.dt, rid)
                if best is None or key > best[0]:
                    best = (key, rid)
        return best[1] if best else None


def kind_of_resource(rid: str, rm: "ResourceMap | None" = None) -> str:
    from .parse_evidence import kind_for
    if rm is not None:
        for o in rm.observations:
            if o.kind:
                return o.kind
    system = rm.system if rm is not None else ""
    return kind_for(system, "", rid)


# ------------------------------------------------------------- attribution law
PREF = {"COMPLETE": {"SUCCESS"}, "PARTIALLY_COMPLETE": {"PARTIAL"}, "NOT_STARTED": {"FAILED"}}


def result_matches(reported_status: str, op) -> bool:
    pref = PREF.get((reported_status or "").strip(), None)
    if not pref:
        return True
    return (op.reported_result or "").strip().upper() in pref


def band_window(rep_at: str):
    rep = _dt(rep_at)
    if rep is None:
        return None
    return (rep - timedelta(minutes=75), rep - timedelta(minutes=45))


def band_ops(activity, rep_at: str) -> list:
    """Deduplicated DELETE_RECORD workflow ops on account resources in the band."""
    win = band_window(rep_at)
    if not win:
        return []
    lo, hi = win
    picked: dict[str, object] = {}
    for op in activity.ops:
        if op.source_system != WORKFLOW_SOURCE or op.op != "DELETE_RECORD":
            continue
        rid = op.resource_id or ""
        if not rid.startswith("account_"):
            continue
        dt = op.dt
        if dt is None or dt < lo or dt > hi:
            continue
        cur = picked.get(rid)
        if cur is None or dt < cur.dt:
            picked[rid] = op
    return sorted(picked.values(), key=lambda o: (o.dt, o.activity_id))


def analytics_ops(activity, rep_at: str) -> list:
    """ANONYMIZE_RECORD ops on analytics resources in [rep-75m, rep+2h]."""
    rep = _dt(rep_at)
    if rep is None:
        return []
    lo = rep - timedelta(minutes=75)
    hi = rep + timedelta(hours=2)
    picked: dict[str, object] = {}
    for op in activity.ops:
        if op.source_system != WORKFLOW_SOURCE or op.op != "ANONYMIZE_RECORD":
            continue
        rid = op.resource_id or ""
        if not rid.startswith("analytics_"):
            continue
        dt = op.dt
        if dt is None or dt < lo or dt > hi:
            continue
        cur = picked.get(rid)
        if cur is None or dt < cur.dt:
            picked[rid] = op
    return sorted(picked.values(), key=lambda o: (o.dt, o.activity_id))
