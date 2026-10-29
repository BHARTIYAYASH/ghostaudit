"""Pipeline: load corpus -> parse evidence -> bind subjects -> decide cases.

Two-tier time validity:

* binding / identity attribution may use ANY evidence regardless of capture
  time;
* state determination and COMPLETE-case citations require both
  ``obs.t <= audit_at`` and the file's manifest ``captured_at <= audit_at``.

Cluster laws (non-NA cases sharing one ``reported_at``):

* the account resources share the DELETE_RECORD band [rep-75m, rep-45m];
  attribution prefers explicitly subject-bound accounts whose op result
  matches the reported lifecycle, then zips the leftover cases with the
  leftover band ops of the SAME result class (cases requested_at DESC,
  ties case_id ASC, ops time-ascending);
* non-deletion text cases (NOT_APPLICABLE candidates) never consume band
  ops; they corroborate via a CLASSIFY_REQUEST op on an account whose
  evidence tokens belong to the subject;
* analytics resources are subject-bound when an attacker-visible identifier
  is present, otherwise zip over ANONYMIZE ops in [rep-75m, rep+2h] that
  are claim-bound to nobody;
* when a cluster's band is empty, family-A accounts fall back to
  account_<user_No> for users 01..10 only.

State law: for a resource id the latest gated non-claim observation wins;
ties break to the earlier file ``captured_at``, then the smaller ``file_id``.
COMPLETE-case verification order: account (delete) first, then the retained
audit record, then redact / anonymize / disabled / blocked.
"""

from __future__ import annotations

import os
import re
import sys

from .activity import ActivityIndex
from .binding import (
    BindingIndex, identity_tokens, kind_of_resource, band_ops, analytics_ops,
    result_matches,
)
from .corpus import Corpus
from .decide import build as build_decision, kind_group, GROUP_PRIORITY, _state_of
from .notapplicable import classify_request_text
from .parse_evidence import EvidenceParser, _dt

FAMILY_NUMERIC_MAX = 10   # user_01..user_10 numeric-fallback families

_CLASS_OF = {"COMPLETE": "S", "PARTIALLY_COMPLETE": "P", "NOT_STARTED": "F"}


def _fid_key(file_id: str):
    """Natural sort key for evidence file ids (evidence_9 < evidence_10)."""
    m = re.search(r"(\d+)", file_id or "")
    if m:
        return (0, int(m.group(1)), file_id or "")
    return (1, 0, file_id or "")


class Pipeline:
    def __init__(self, dataset_dir: str, image_facts_path: str | None = None,
                 verbose: bool = False) -> None:
        self.corpus = Corpus(dataset_dir)
        self.verbose = verbose
        self.image_facts = self._load_image_facts(image_facts_path)
        self.parser = self._build_parser()
        self.activity = self._build_activity()
        self.binding = BindingIndex(self.corpus, self.parser.observations, self.activity)
        self.file_scopes = self.parser.file_scopes
        self._analytics_pairs: dict[str, str | None] = {}

    # ------------------------------------------------------------------ setup
    def _load_image_facts(self, path: str | None) -> list:
        import json
        candidates = [path] if path else []
        here = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(here, "data", "image_facts.json"))
        for cand in candidates:
            if cand and os.path.exists(cand):
                try:
                    with open(cand, "r", encoding="utf-8-sig") as fh:
                        doc = json.load(fh)
                    if isinstance(doc, list):
                        return [f for f in doc if isinstance(f, dict)]
                    if isinstance(doc, dict):
                        return [f for f in doc.values() if isinstance(f, dict)]
                except Exception as exc:
                    print(f"[ghostaudit] warning: image facts unusable: {exc}",
                          file=sys.stderr)
        return []

    def _build_parser(self):
        parser = EvidenceParser(self.corpus, self.image_facts)
        parser.parse_all()
        return parser

    def _build_activity(self) -> ActivityIndex:
        return ActivityIndex(self.corpus)

    # ------------------------------------------------------------------- run
    def run(self, rows=None) -> dict:
        rows = list(rows) if rows is not None else list(self.corpus.requests)
        rows.sort(key=lambda r: r["case_id"])

        na_text = {r["case_id"]: classify_request_text(r.get("request_text") or "")
                   for r in rows}

        ident_of: dict[str, object] = {}
        for row in rows:
            ident_of[row["case_id"]] = self._resolve_identity(row)

        self._analytics_pairs.clear()
        clusters: dict[str, list] = {}
        # non-deletion text cases never consume band ops: exclude them from
        # the account pairing clusters
        for row in rows:
            if na_text[row["case_id"]]:
                continue
            clusters.setdefault((row.get("reported_at") or "").strip(), []).append(row)

        account_of: dict[str, str | None] = {}
        for rep, crows in sorted(clusters.items()):
            account_of.update(self._assign_accounts(rep, crows, ident_of))
            self._pair_analytics(rep, crows, ident_of, account_of, self._analytics_pairs)

        # debug-visible cluster state (fields are plain dicts, no behaviour)
        self.cluster_of = dict(clusters)
        self.account_of = dict(account_of)
        self.pairs = dict(self._analytics_pairs)

        results: dict[str, tuple] = {}
        for row in rows:
            cid = row["case_id"]
            ident = ident_of[cid]
            ctx = self._case_context(row, ident)
            ctx["account"] = account_of.get(cid)
            ctx["audit_record"] = self._audit_record(ident)
            ctx["audit_at"] = _dt(row.get("audit_at") or "")
            self._build_landscape(ctx)
            ctx["account_family_file"] = self._account_family_file(
                ctx["audit_at"], ctx["entries"])
            if not na_text[cid]:
                results[cid] = build_decision(ctx)
                continue
            aid = self._classified_account(ident, ctx["audit_at"])
            results[cid] = ("NOT_APPLICABLE", []) if aid else build_decision(ctx)
        return results

    # ------------------------------------------------------------- identities
    def _resolve_identity(self, row):
        email = (row.get("email") or "").strip().lower()
        ident = self.corpus.resolve_user(email)
        if ident is None:
            historical = [
                ev for ev in self.corpus.audit_log
                if (ev.get("old_value") or "").strip().lower() == email
                or (ev.get("new_value") or "").strip().lower() == email
            ]
            if historical:
                ident = self.corpus.new_identity_for_audit(historical[0]["user_id"])
        return ident

    # ------------------------------------------------------- account binding
    def _assign_accounts(self, rep, crows, ident_of) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        ops = band_ops(self.activity, rep)
        if not ops:
            # family numeric fallback when the cluster's band was empty
            for crow in crows:
                out[crow["case_id"]] = \
                    self._numeric_family_account(crow, ident_of[crow["case_id"]])
            return out

        def mine_of(crow) -> set:
            ident = ident_of[crow["case_id"]]
            return identity_tokens(ident) if ident else set()

        def tokens_of(rid) -> set:
            rm = self.binding.resources.get(rid)
            return rm.tokens if rm else set()

        assigned: set[str] = set()

        # pass 1: explicit subject binding inside the band, result-pref first
        for crow in crows:
            mine = mine_of(crow)
            if not mine:
                continue
            pref = [op for op in ops if result_matches(crow.get("reported_status"), op)]
            for op in (pref or ops):
                toks = tokens_of(op.resource_id)
                if toks and toks <= mine and op.resource_id not in assigned:
                    out[crow["case_id"]] = op.resource_id
                    assigned.add(op.resource_id)
                    break

        # pass 2: result-class zip of leftovers:
        #   cases requested_at DESC (ties case_id ASC) <-> class ops time-ASC
        case_cls: dict[str, list] = {"S": [], "P": [], "F": []}
        for crow in crows:
            if crow["case_id"] in out:
                continue
            key = _CLASS_OF.get((crow.get("reported_status") or "").strip(), "F")
            case_cls[key].append(crow)
        op_cls: dict[str, list] = {"S": [], "P": [], "F": []}
        for op in ops:
            if op.resource_id in assigned:
                continue
            res = (op.reported_result or "").strip().upper()
            if res[:1] in ("S", "P", "F"):
                op_cls[res[:1]].append(op)
        for key, cases in case_cls.items():
            if not cases:
                continue
            # two-stage stable sort: case_id ASC, then requested_at DESC
            cases.sort(key=lambda c: c["case_id"])
            cases.sort(key=lambda c: (c.get("requested_at") or ""), reverse=True)
            oi = 0
            pool = op_cls[key]
            for crow in cases:
                mine = mine_of(crow)
                while oi < len(pool):
                    op = pool[oi]
                    toks = tokens_of(op.resource_id)
                    if toks and any(t not in mine for t in toks):
                        oi += 1      # foreign-claimed: unusable for this cluster
                        continue
                    out[crow["case_id"]] = op.resource_id
                    assigned.add(op.resource_id)
                    oi += 1
                    break
                else:
                    out[crow["case_id"]] = None
        return out

    def _numeric_family_account(self, crow, ident) -> str | None:
        """account_<user_no zfill 3> only for users 01..10, unclaimed."""
        uid = ident.user_id if ident else ""
        m = re.fullmatch(r"user_(\d+)", uid or "")
        if not m:
            return None
        nnum = int(m.group(1))
        if nnum > FAMILY_NUMERIC_MAX:
            return None
        cand = "account_" + m.group(1).zfill(3)
        rm = self.binding.resources.get(cand)
        mine = identity_tokens(ident) if ident else set()
        if rm and any(tok not in mine for tok in rm.tokens):
            return None
        return cand

    # ---------------------------------------------------- analytics pairing
    def _pair_analytics(self, rep, crows, ident_of, account_of, pairs) -> None:
        # subject-bound analytics resources are used directly
        for crow in crows:
            ident = ident_of[crow["case_id"]]
            if ident is None:
                continue
            mine = identity_tokens(ident)
            if not mine:
                continue
            hits = []
            for rid, rm in self.binding.resources.items():
                if kind_of_resource(rid, rm) != "ANALYTICS_PROFILE" \
                        and not rid.startswith("analytics_"):
                    continue
                if rm.tokens & mine:
                    hits.append(rid)
            if len(hits) == 1:
                pairs[crow["case_id"]] = hits[0]
            elif hits:
                pairs[crow["case_id"]] = None   # ambiguous binding: no pair

        # remaining cluster cases: only violation-free members (cases whose
        # own landscape has no policy violation and therefore end COMPLETE)
        # may receive a paired analytics resource, zipping requested_at DESC
        # over unclaimed ANONYMIZE ops time-ascending. Subjects preserved as
        # an account tombstone (redact path) never receive a paired
        # analytics anonymization.
        participants = []
        for crow in crows:
            cid = crow["case_id"]
            if cid in pairs:
                continue
            audit = _dt(crow.get("audit_at") or "")
            toks = identity_tokens(ident_of[cid]) if ident_of[cid] else set()
            core = self._core_entries(toks, account_of.get(cid), audit)
            if any(obs is not None and _state_of(kind, obs) is not None
                   for _, kind, obs in core.values()):
                continue
            if any(kind == "ACCOUNT_TOMBSTONE" for _, kind, _ in core.values()):
                continue
            participants.append(crow)
        if not participants:
            return
        ops = [op for op in analytics_ops(self.activity, rep) if self._unclaimed(op)]
        participants.sort(key=lambda c: c["case_id"])
        participants.sort(key=lambda c: (c.get("requested_at") or ""), reverse=True)
        for i, crow in enumerate(participants):
            if i < len(ops):
                pairs[crow["case_id"]] = ops[i].resource_id

    def _unclaimed(self, op) -> bool:
        rm = self.binding.resources.get(op.resource_id)
        return not (rm and rm.tokens)

    # ------------------------------------------------------------ state law
    def _state_obs(self, rid, audit):
        """Latest gated non-claim observation; ties -> earlier captured_at,
        then smaller file_id. Whole-file gate: the file's manifest
        captured_at must also be <= audit_at."""
        rm = self.binding.resources.get(rid)
        if not rm:
            return None
        best = None
        best_key = None
        for obs in rm.observations:
            if obs.claim:
                continue
            odt = obs.dt
            if odt is None:
                continue
            cap = _dt(obs.captured_at) if obs.captured_at else odt
            if cap is None:
                continue
            if audit is not None and (odt > audit or cap > audit):
                continue
            key = (odt, cap, _fid_key(obs.file_id or ""))
            if best_key is None or self._key_wins(key, best_key):
                best, best_key = obs, key
        return best

    @staticmethod
    def _key_wins(key, cur) -> bool:
        # later obs.dt wins; tie -> earlier captured_at; tie -> smaller file_id
        if key[0] != cur[0]:
            return key[0] > cur[0]
        if key[1] != cur[1]:
            return key[1] < cur[1]
        return key[2] < cur[2]

    def _account_state(self, rid, audit) -> str | None:
        obs = self._state_obs(rid, audit)
        return obs.state if obs is not None else None

    def _audit_record(self, ident) -> str | None:
        return self.binding.latest_audit_record(ident) if ident else None

    # -------------------------------------------------- NOT_APPLICABLE gate
    def _classified_account(self, ident, audit) -> str | None:
        """Account whose CLASSIFY_REQUEST annotation binds this subject."""
        mine = identity_tokens(ident) if ident else set()
        if not mine:
            return None
        for rid, rm in sorted(self.binding.resources.items()):
            if not (rm.tokens and rm.tokens <= mine):
                continue
            for op in rm.ops:
                if getattr(op, "op", "") != "CLASSIFY_REQUEST":
                    continue
                if op.dt is not None and audit is not None and op.dt > audit:
                    continue
                return rid
        return None

    # ------------------------------------------------------------ landscape
    def _case_context(self, row, ident) -> dict:
        return {"case_id": row["case_id"], "row": row, "ident": ident,
                "ident_tokens": identity_tokens(ident) if ident else set(),
                "entries": [], "account": None, "audit_record": None,
                "audit_at": None, "account_family_file": None}

    def _core_entries(self, toks: set, account, audit) -> dict:
        """Subject-bound entries + the band account (no paired analytics)."""
        rid_entry: dict[str, tuple] = {}
        for rid, rm in self.binding.resources.items():
            if not (rm.tokens & toks):
                continue
            kind = kind_of_resource(rid, rm)
            obs = self._state_obs(rid, audit)
            self._consider(rid_entry, rid, kind, obs, kind_group(kind))
        if account and account not in rid_entry:
            self._consider(rid_entry, account, "USER_PROFILE",
                           self._state_obs(account, audit), "delete")
        return rid_entry

    def _has_core_violation(self, row, ident, account, audit) -> bool:
        """True when the case's own (pre-analytics) landscape already
        carries a policy violation: such cases never receive paired
        analytics resources."""
        toks = identity_tokens(ident) if ident else set()
        for rid, kind, obs in self._core_entries(toks, account, audit).values():
            if obs is None:
                continue
            if _state_of(kind, obs) is not None:
                return True
        return False

    def _build_landscape(self, ctx: dict) -> None:
        row, audit, toks = ctx["row"], ctx["audit_at"], ctx["ident_tokens"]
        rid_entry = self._core_entries(toks, ctx.get("account"), audit)
        analytics = self._analytics_pairs.get(ctx["case_id"])
        if analytics and analytics not in rid_entry:
            self._consider(rid_entry, analytics, "ANALYTICS_PROFILE",
                           self._state_obs(analytics, audit), "anon")
        audit_rid = ctx.get("audit_record")
        if audit_rid and audit_rid not in rid_entry:
            self._consider(rid_entry, audit_rid, "SECURITY_AUDIT_LOG",
                           self._state_obs(audit_rid, audit), "retain")
        ctx["entries"] = sorted(rid_entry.values(), key=lambda e: e[0])

    @staticmethod
    def _consider(rid_entry: dict, rid, kind, obs, group: str) -> None:
        if group == "retain" and kind != "SECURITY_AUDIT_LOG":
            return
        cur = rid_entry.get(rid)
        if cur is None:
            rid_entry[rid] = (rid, kind, obs)
            return
        gp_new = GROUP_PRIORITY.get(group, 9)
        gp_cur = GROUP_PRIORITY.get(kind_group(cur[1]), 9)
        if gp_new < gp_cur:
            rid_entry[rid] = (rid, kind, obs)
            return
        if gp_new > gp_cur:
            return
        # same priority: keep the observation with more authority
        if obs is not None and (cur[2] is None
                                or (obs.dt, obs.file_id) > (cur[2].dt, cur[2].file_id)):
            rid_entry[rid] = (rid, kind, obs)

    # ----------------------------------------------------- account-family file
    def _account_family_file(self, audit, entries=()) -> str | None:
        """Latest gated file whose account-family census carries rows: the
        customer_profiles tables and the deleted_customer_references
        (tombstone) registers together form the account family."""
        if audit is None:
            return None
        family_ns = ("customer_profiles", "deleted_customer_references")
        best = None
        for fid, scope in self.parser.file_scopes.items():
            cap = scope.get("captured")
            if cap is None or cap > audit:
                continue
            cols = scope.get("collections") or {}
            rows = scope.get("rows") or {}
            fam = 0
            for c in cols:
                if any(c.startswith(ns) for ns in family_ns):
                    fam += rows.get(c) or 0
            if not fam:
                continue
            if best is None or (cap, _fid_key(fid)) > (best[0], _fid_key(best[1])):
                best = (cap, fid)
        return best[1] if best else None
