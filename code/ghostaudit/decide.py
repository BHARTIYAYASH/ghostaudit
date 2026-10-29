"""Decision engine: verdict + canonically ordered steps per case.

Canonical orderings (mirrors the required serialization):

* FINDING       REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII,
                REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK;
                within one operation: system_id asc, then resource_id asc.
* REMEDIATION   DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD,
                REDACT_RECORD, ANONYMIZE_RECORD.
* VERIFICATION  VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT,
                VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED,
                VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED.

COMPLETE cases carry only evidence-backed verifications; INCOMPLETE cases cite
findings, empty-evidence remediations and empty-evidence verifications.
"""

from __future__ import annotations

DELETE_KINDS = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE", "USER_CONTACT",
}
REDACT_KINDS = {"SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG"}
ANON_KINDS = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
RETAIN_KINDS = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}

GROUP_PRIORITY = {"delete": 0, "redact": 1, "anon": 2, "flow": 3, "backup": 4, "retain": 5}

# COMPLETE-case verification order: account (delete) first, retained
# audit record, then redact / anonymize / disabled / blocked.
_COMPLETE_RANK = {"delete": 0, "retain": 1, "redact": 2, "anon": 3,
                  "flow": 4, "backup": 5}

FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = [
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
]


def kind_group(kind: str) -> str:
    if kind in RETAIN_KINDS:
        return "retain"
    if kind == "BACKUP_ARCHIVE":
        return "backup"
    if kind == "DATA_FLOW":
        return "flow"
    if kind in ANON_KINDS:
        return "anon"
    if kind in REDACT_KINDS:
        return "redact"
    return "delete"


def _state_of(kind: str, obs):
    """(group, violated, remediation op, finding op, finding state)."""
    group = kind_group(kind)
    st = obs.state
    if group == "flow":
        return None if st != "ACTIVE" else (True, "DISABLE_DATA_FLOW", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE")
    if group == "backup":
        return None if st != "ACTIVE" else (True, "BLOCK_RESTORE", "REPORT_RESTORE_RISK", "ACTIVE")
    if group == "retain":
        return None
    if st == "PRESENT":
        if not obs.identifiable and group == "delete" and kind == "USER_PROFILE":
            return None     # tombstone-preserved profile: stable reference only
        if group == "delete":
            return (True, "DELETE_RECORD", "REPORT_REMAINING_RECORD", "PRESENT")
        if group == "redact":
            return (True, "REDACT_RECORD", "REPORT_EXPOSED_PII", "PRESENT")
        return (True, "ANONYMIZE_RECORD", "REPORT_EXPOSED_PII", "PRESENT")
    return None


def _step(no, phase, op, system, rid, state, evidence=""):
    return {
        "step_no": no,
        "phase": phase,
        "system_id": system,
        "resource_id": rid,
        "operation": op,
        "state": state,
        "evidence_id": evidence,
    }


def _sort_key(step, findings_first=False):
    phase = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}[step["phase"]]
    table = {"FINDING": FINDING_ORDER, "REMEDIATION": REMEDIATION_ORDER, "VERIFICATION": VERIFICATION_ORDER}
    op_order = table[step["phase"]]
    try:
        oi = op_order.index(step["operation"])
    except ValueError:
        oi = len(op_order)
    return (phase, oi, step["system_id"], step["resource_id"])


def _renumber(steps, findings_first=False):
    steps.sort(key=lambda s: _sort_key(s, findings_first))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return steps


VERIFY_FOR_RESULT_STATE = {
    "ABSENT": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACTED": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZED": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "DISABLED": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    "BLOCKED": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}


def build(ctx) -> tuple[str, list[dict]]:
    """ctx carries everything decided upstream for one case."""
    entries = ctx["entries"]          # [(rid, kind, obs_or_None)]
    violations = []
    compliants = []
    for rid, kind, obs in entries:
        if obs is None:
            continue
        key = _state_of(kind, obs)
        if key is None:
            compliants.append((rid, kind, obs))
        else:
            violations.append((rid, kind, obs, key))

    audit_record = ctx.get("audit_record")

    # --------------------------------------------------------------- COMPLETE
    if not violations:
        raw = []
        for rid, kind, obs in compliants:
            if kind_group(kind) == "retain":
                if rid == audit_record:
                    raw.append((1, rid, _step(0, "VERIFICATION", "VERIFY_RECORD_PRESENT",
                                              obs.system or "security_service", rid, "PRESENT", obs.file_id)))
                continue
            grp = kind_group(kind)
            if grp == "delete" and rid == ctx.get("account") and obs.state == "PRESENT":
                continue  # cannot happen in a compliant branch
            v = VERIFY_FOR_RESULT_STATE.get(obs.state)
            if v is None:
                continue
            raw.append((_COMPLETE_RANK[kind_group(kind)], rid,
                        _step(0, "VERIFICATION", v[0], obs.system, rid, v[1], obs.file_id)))
        # account with no gated observation: absence proven family-wide
        acct = ctx.get("account")
        acct_has_obs = any(r == acct and obs is not None for r, _, obs in entries)
        if acct and not acct_has_obs:
            fid = ctx["account_family_file"]
            if fid:
                raw.append((0, "_account", _step(0, "VERIFICATION", "VERIFY_RECORD_ABSENT",
                                                 "account_service", acct, "ABSENT", fid)))
        steps = [s for _r, _rid, s in sorted(raw, key=lambda t: (t[0], t[1]))]
        if steps:
            return "COMPLETE", _renumber(steps)
        return "INCOMPLETE", []

    # ------------------------------------------------------------- INCOMPLETE
    steps = []
    for rid, kind, obs, (violated, rem_op, find_op, st) in violations:
        steps.append(_step(0, "FINDING", find_op, obs.system, rid, st, obs.file_id))
    for rid, kind, obs, (violated, rem_op, find_op, st) in violations:
        rr_state = {"BLOCK_RESTORE": "BLOCKED", "DISABLE_DATA_FLOW": "DISABLED",
                    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
                    "ANONYMIZE_RECORD": "ANONYMIZED"}[rem_op]
        steps.append(_step(0, "REMEDIATION", rem_op, obs.system, rid, rr_state, ""))
    # the account (when untouched) is still re-checked after remediation
    account = ctx.get("account")
    if account and not any(r == account for r, _, _, _ in violations):
        steps.append(_step(0, "VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", account, "ABSENT", ""))
    for rid, kind, obs, (violated, rem_op, find_op, st) in violations:
        rr_state = {"BLOCK_RESTORE": "BLOCKED", "DISABLE_DATA_FLOW": "DISABLED",
                    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
                    "ANONYMIZE_RECORD": "ANONYMIZED"}[rem_op]
        vop = VERIFICATION_ORDER[-2] if rr_state == "DISABLED" else (
            VERIFICATION_ORDER[-1] if rr_state == "BLOCKED" else
            {"ABSENT": VERIFICATION_ORDER[0], "REDACTED": VERIFICATION_ORDER[2],
             "ANONYMIZED": VERIFICATION_ORDER[3]}[rr_state])
        steps.append(_step(0, "VERIFICATION", vop, obs.system, rid, rr_state, ""))
    if audit_record:
        steps.append(_step(0, "VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service",
                           audit_record, "PRESENT", ""))
    return "INCOMPLETE", _renumber(steps)
