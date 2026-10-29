"""Evidence parsing: normalize every evidence family into ``Observation``s.

An ``Observation`` captures ONE verifiable fact about ONE resource, as seen by
one evidence source:

    file_id      evidence id (participant-visible citation)
    system       owning system (account_service, search_service, ...)
    resource_id  resource key (account_9797, search_052, ...)
    kind         data category from deletion_rules.csv vocabulary
    state        normalized state code (PRESENT, ABSENT, REDACTED, ANONYMIZED,
                 ACTIVE, DISABLED, BLOCKED)
    identifiable True when a direct identifier of the subject is exposed
    subjects     identifier strings found in/for this observation
    t            observation time; obs_time when stated else file capture time
    claim        True for claims (activity/workflow statuses) that are not yet
                 backed by an inspection of the stored data

Timestamp contract: an observation is only usable for a case when
``t <= audit_at`` (inclusive).
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

STATE_PRESENT = "PRESENT"
STATE_ABSENT = "ABSENT"
STATE_REDACTED = "REDACTED"
STATE_ANONYMIZED = "ANONYMIZED"
STATE_ACTIVE = "ACTIVE"
STATE_DISABLED = "DISABLED"
STATE_BLOCKED = "BLOCKED"
STATE_RETAINED = "RETAINED"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+\d[\d\s\-()]{6,}")
_HASH_RE = re.compile(r"\b[0-9a-f]{64}\b", re.I)
_USERID_RE = re.compile(r"\buser_\d+\b", re.I)
_RESOURCE_RE = re.compile(r"\b[a-z]+_(?:\d{1,4})\b", re.I)


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[: len(fmt) + 2], fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def subjects_from_text(text: str) -> set[str]:
    """Extract raw identifier tokens from free text (binding happens later)."""
    subs: set[str] = set()
    for m in _EMAIL_RE.findall(text or ""):
        subs.add(m.lower())
    for m in _HASH_RE.findall(text or ""):
        subs.add(m.lower())
    for m in _USERID_RE.findall(text or ""):
        subs.add(m.lower())
    for m in _PHONE_RE.findall(text or ""):
        subs.add("p:" + "".join(ch for ch in m if ch.isdigit()))
    return subs


# --------------------------------------------------------------- data classes
_SCOPE_SUFFIX_RE = re.compile(
    r"(_failover_replica|_failover|_read_replica|_reporting_replica|_regional_replicas|"
    r"_replica|_primary|_snapshot|_export)$")


def _normalize_scope_name(name: str) -> str:
    n = (name or "").strip().lower()
    for _ in range(2):
        n = _SCOPE_SUFFIX_RE.sub("", n)
    return n
@dataclass
class Observation:
    file_id: str
    system: str
    resource_id: str
    kind: str
    state: str
    identifiable: bool = False
    subjects: set[str] = field(default_factory=set)
    t: str = ""                      # ISO string for the fact
    captured_at: str = ""            # manifest capture time of the file
    claim: bool = False              # claim vs. inspected state
    note: str = ""

    @property
    def dt(self):
        return _dt(self.t) or datetime.min.replace(tzinfo=timezone.utc)


@dataclass
class WorkflowOp:
    activity_id: str
    event_time: str
    op: str                          # DELETE_RECORD, ANONYMIZE_RECORD, ...
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    subjects: set[str] = field(default_factory=set)

    @property
    def dt(self):
        return _dt(self.event_time) or datetime.min.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------ record-kind map
def kind_for(system: str, collection: str, resource_id: str) -> str:
    """Map (system, collection/table, resource prefix) -> data_category."""
    rid = (resource_id or "").lower()
    prefix = rid.split("_", 1)[0] if "_" in rid else rid
    sys = (system or "").lower()
    collection = (collection or "").lower()

    if "tombstone" in collection or prefix == "tombstone":
        return "ACCOUNT_TOMBSTONE"
    if "contact" in collection and "connector" not in collection:
        return "USER_CONTACT"
    if prefix.startswith("account"):
        return "USER_PROFILE"
    if prefix.startswith("search"):
        return "SEARCH_INDEX_ENTRY"
    if prefix.startswith("cache"):
        return "CACHE_ENTRY"
    if prefix.startswith("export"):
        return "USER_EXPORT"
    if prefix.startswith("marketing"):
        return "MARKETING_PROFILE"
    if prefix.startswith("backup"):
        return "BACKUP_ARCHIVE"
    if prefix.startswith("data_flow"):
        return "DATA_FLOW"
    if prefix.startswith("audit_record"):
        return "SECURITY_AUDIT_LOG"
    if prefix.startswith("email_delivery"):
        return "EMAIL_DELIVERY_LOG"
    if prefix.startswith("legal_hold") or "retained_order" in collection or "legal" in collection:
        return "LEGAL_HOLD_RECORD"
    if prefix.startswith("support") or sys == "support_platform":
        if "attachment" in collection or "attachment" in sys:
            return "SUPPORT_ATTACHMENT"
        return "SUPPORT_MESSAGE"
    if prefix.startswith("object"):
        return "SUPPORT_ATTACHMENT"
    if prefix.startswith("analytics"):
        if "contact" in collection or "contact" in sys:
            return "USER_CONTACT"
        return "ANALYTICS_PROFILE"
    if prefix.startswith("telemetry") or "telemetry" in collection:
        return "PRODUCT_TELEMETRY"
    if sys == "account_service":
        return "USER_PROFILE"
    if sys == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if sys == "analytics_platform":
        return "ANALYTICS_PROFILE"
    if sys == "support_platform":
        return "SUPPORT_MESSAGE"
    if sys == "integration_service":
        return "DATA_FLOW"
    if sys == "backup_service":
        return "BACKUP_ARCHIVE"
    if sys == "security_service":
        return "SECURITY_AUDIT_LOG"
    if sys == "export_service":
        return "USER_EXPORT"
    if sys == "identity_service":
        return "ACCOUNT_TOMBSTONE"
    if sys == "marketing_platform":
        return "MARKETING_PROFILE"
    if sys == "notification_service":
        return "EMAIL_DELIVERY_LOG"
    if sys == "cache_service":
        return "CACHE_ENTRY"
    if sys == "legal_service":
        return "LEGAL_HOLD_RECORD"
    return collection.upper() if collection else sys.upper()


# ------------------------------------------------------------------- parsers
def _email(v):
    return (v or "").strip().lower()


class EvidenceParser:
    """Parses every participant-visible evidence file into observations."""

    def __init__(self, corpus, image_facts: list[dict] | None = None) -> None:
        self.corpus = corpus
        self.dataset_dir = corpus.dataset_dir
        self.observations: list[Observation] = []
        self.image_facts = image_facts or []
        # file_id -> {"captured": datetime|None, "collections": {normalized names}}
        self.file_scopes: dict[str, dict] = {}

    # ------------------------------------------------------------- dispatch
    def _add_scope(self, fid: str, name: str) -> None:
        nm = _normalize_scope_name(name)
        if nm:
            self.file_scopes.setdefault(fid, {"captured": None, "collections": set()})
            self.file_scopes[fid]["collections"].add(nm)

    def _scope_rows(self, fid: str, name: str, n: int = 1) -> None:
        nm = _normalize_scope_name(name)
        if not nm:
            return
        self.file_scopes.setdefault(fid, {"captured": None, "collections": set()})
        rows = self.file_scopes[fid].setdefault("rows", {})
        rows[nm] = rows.get(nm, 0) + n

    def parse_all(self) -> list[Observation]:
        for row in self.corpus.manifest:
            fid, fpath = row["file_id"], row["file_path"]
            captured = row.get("captured_at", "")
            origin = row.get("origin", "")
            abspath = self.corpus.evidence_path(fpath)
            ext = os.path.splitext(fpath)[1].lower()
            self.file_scopes[fid] = {"captured": _dt(captured), "collections": set(), "path": fpath}
            try:
                if ext == ".sql":
                    self._parse_sql(fid, abspath, captured)
                elif ext == ".json":
                    self._parse_json(fid, abspath, captured)
                elif ext == ".txt":
                    self._parse_txt(fid, abspath, captured)
                elif ext == ".log":
                    self._parse_log(fid, abspath, captured)
                elif ext == ".pdf":
                    self._parse_pdf(fid, abspath, captured)
                elif ext == ".png":
                    self._parse_png(fid, row, captured)
            except Exception as exc:  # keep a clean run usable
                print(f"[ghostaudit] warning: failed to parse {fpath}: {exc}", file=sys.stderr)
            for ob in self.observations:
                if not ob.captured_at:
                    ob.captured_at = captured
        for fact in self.image_facts:
            self._emit_image_facts(fact)
        return self.observations

    # ------------------------------------------------------------- SQL files
    def _parse_sql(self, fid: str, path: str, captured: str) -> None:
        text = open(path, encoding="utf-8-sig", errors="replace").read()
        header_dt = None
        m = re.search(r"--\s*Captured at:\s*(\S+)", text)
        if m:
            header_dt = _dt(m.group(1)) or header_dt
        topology = ""
        m = re.search(r"--\s*Database topology:\s*(\S+)", text)
        if m:
            topology = m.group(1)
        # tables: CREATE TABLE <name> ( ... );  -- may span many lines
        table_columns: dict[str, list[str]] = {}
        for tm in re.finditer(r"CREATE TABLE\s+\"?([\w]+?)\"?\s*\((.*?)\)\s*;", text, re.S | re.I):
            name, block = tm.group(1), tm.group(2)
            # CHECK ( ... ) constraints may contain commas and nested parens
            # (e.g. CHECK (x IN ('0','1'))) - drop them before splitting
            block = re.sub(r"CHECK\s*\((?:[^()]|\([^()]*\))*\)", "", block, flags=re.I)
            cols = []
            for col in block.split(","):
                w = col.strip().strip('"').split()
                if w:
                    cols.append(w[0].strip('"'))
            table_columns[name.lower()] = cols
        table_order = []  # order of table definitions to map INSERTs to columns
        last_table = ""
        for sm in re.finditer(r"CREATE TABLE\s+\"?([\w]+?)\"?\s*\(", text, re.I):
            table_order.append(sm.group(1).lower())
            self._add_scope(fid, sm.group(1).lower())
        pending = 0
        insert_ctx = ""
        for line in text.splitlines():
            tm = re.match(r"CREATE TABLE\s+\"?([\w]+?)\"?\s*\(", line.strip(), re.I)
            if tm:
                pending = 1  # columns may follow on subsequent lines
                continue
            if pending and not line.strip().lower().startswith("insert into"):
                if re.search(r";\s*$", line):
                    pending = 0
                continue
            ins = re.match(r"INSERT INTO \"?([\w]+?)\"?\s*VALUES\s*\((.*)\);\s*$", line.strip(), re.I)
            if not ins:
                continue
            table, payload = ins.group(1), ins.group(2)
            vals = _split_sql_values(payload)
            cols = table_columns.get(table.lower()) or []
            if cols and len(vals) == len(cols):
                rec = dict(zip(cols, vals))
            else:
                rec = {"_values": vals}
            self._record_from_row(fid, table, rec, captured, topology, header_dt)

    def _record_from_row(self, fid, table, rec, t, topology, header_dt) -> None:
        rid = rec.get("resource_id") or (rec["_values"][0] if rec.get("_values") else "")
        if not rid:
            return
        self._scope_rows(fid, table)
        # embedded JSON record (uniform "customer_data_*" snapshots)
        rj = rec.get("record_json")
        if rj:
            try:
                inner = json.loads(rj)
            except Exception:
                inner = None
            if inner:
                system = rec.get("origin_system") or _system_from_table(table)
                self._emit_from_generic_record(
                    fid, system or "", rid, inner, rec.get("updated_at") or t,
                    collection=rec.get("collection_name") or "",
                )
                return
        if rec.get("_values") is None:
            rec["resource_id"] = rid
            rec["system"] = rec.get("system") or rec.get("origin_system") or _system_from_table(table)
            self._emit_from_generic_record(fid, rec["system"], rid, rec, rec.get("updated_at") or t, collection=table)
        else:
            vals = rec["_values"]
            self._emit_from_generic_record(fid, table, rid, dict(zip(_GUESS_COLS[: len(vals)], vals)), t, collection=table)

    # ------------------------------------------------------- generic records
    def _emit_from_generic_record(self, fid, system, rid, rec, t, collection=""):
        """Fill an observation from a mostly-generic JSON/dict record."""
        rid = rec.get("resource_id") or rid
        if not rid:
            return
        # index_queries: each hit document is its own observation
        hits = rec.get("hits")
        if isinstance(hits, dict):
            docs = hits.get("documents")
            if isinstance(docs, list) and docs:
                emitted = False
                for d in docs:
                    if not isinstance(d, dict):
                        continue
                    sub = {k: v for k, v in rec.items() if k != "hits"}
                    sub["document"] = d
                    self._emit_from_generic_record(fid, system, d.get("resource_id") or rid, sub, t, collection)
                    emitted = True
                return
            total = hits.get("total")
            if not emitted and (total in (0, "0", None)):
                state = STATE_ABSENT if total in (0, "0") else None
                if state:
                    self.observations.append(Observation(
                        file_id=fid, system=system, resource_id=rid,
                        kind=kind_for(system, collection, rid), state=state,
                        identifiable=False, subjects=set(), t=t or ""))
                    return
        system = rec.get("system") or system or rec.get("origin_system") or _service_from_resource(rid)
        collection = rec.get("collection") or rec.get("collection_name") or collection or rec.get("record_type") or rec.get("data_store") or ""
        collection = str(collection)
        kind = kind_for(system, collection, rid)

        # profile_lookups semantics: status_code + embedded profile
        prof = rec.get("profile")
        if isinstance(prof, dict):
            flat = dict(rec)
            flat.update(rec["profile"])
            rec = {k: v for k, v in flat.items() if k != "profile"}
            kind = kind_for(system, collection, rid)

        subjects = set()
        for key in ("subject_reference", "customer_reference", "user_id", "email", "owner_email",
                    "customer_email", "requester_email", "email_hash", "phone", "requester_phone",
                    "requester_name", "full_name", "display_name", "owner_phone", "subject_selector",
                    "subject_key", "lookup_key", "match_key", "correlation_key", "matched_value"):
            v = rec.get(key)
            if isinstance(v, str):
                subjects |= subjects_from_text(v)
            elif isinstance(v, dict):
                subjects |= subjects_from_text(" ".join(str(x) for x in v.values()))
        doc = rec.get("document") or rec.get("profile") or rec.get("profile_dto")
        if isinstance(doc, dict):
            for v in doc.values():
                if isinstance(v, str):
                    subjects |= subjects_from_text(v)
        notes = str(rec.get("message_text") or rec.get("message_excerpt") or "")
        subjects |= subjects_from_text(notes)
        if subjects:
            subjects -= _resource_ids(subjects)

        state = None
        identifiable = False

        # retention-kind records keep the required retained record
        if kind in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
            self.observations.append(Observation(
                file_id=fid, system=system, resource_id=rid, kind=kind,
                state=STATE_RETAINED, identifiable=False, subjects=subjects, t=t or ""))
            return

        # ---- explicit status/flag fields --------------------------------
        for key, mapping in (
            ("status_code", {200: STATE_PRESENT, 404: STATE_ABSENT, 410: STATE_ABSENT, 403: STATE_ABSENT}),
            ("result", {"FOUND": STATE_PRESENT, "NOT_FOUND": STATE_ABSENT,
                        "IDENTIFIABLE": STATE_PRESENT, "REDACTED": STATE_REDACTED,
                        "ANONYMIZED": STATE_ANONYMIZED, "ACTIVE": STATE_ACTIVE}),
            ("account_status", {"ACTIVE": STATE_PRESENT, "DELETION_PENDING": STATE_PRESENT, "DELETED": STATE_ABSENT}),
        ):
            if key == "account_status" and kind == "ACCOUNT_TOMBSTONE":
                continue    # tombstones use their own redaction law below
            v = rec.get(key)
            if v is None:
                continue
            for cand in (v, str(v).strip().upper(), str(v).strip()):
                if isinstance(v, int) and v in mapping:
                    state = mapping[v]
                    break
                s = str(v)
                if s.isascii() and s.isdigit():
                    try:
                        if int(s) in mapping:
                            state = mapping[int(s)]
                            break
                    except Exception:
                        pass
                su = s.strip().upper()
                if su in mapping:
                    state = mapping[su]
                    break
            if state is not None:
                break
        for key, tval, fval in (
            ("enabled", STATE_ACTIVE, STATE_DISABLED),
            ("restore_allowed", STATE_ACTIVE, STATE_BLOCKED),
            ("download_available", STATE_PRESENT, STATE_ABSENT),
            ("available", STATE_PRESENT, STATE_ABSENT),
        ):
            v = rec.get(key)
            if v is None:
                continue
            b = None
            if isinstance(v, bool):
                b = v
            elif str(v).strip().lower() in ("true", "false", "0", "1"):
                b = str(v).strip().lower() in ("true", "1")
            if b is not None:
                state = tval if b else fval
                break

        # ---- direct-identifier detection ---------------------------------
        direct_keys = ("email", "phone", "email_hash", "full_name", "display_name",
                       "requester_email", "requester_name", "requester_phone",
                       "owner_email", "owner_phone", "customer_email")
        has_direct = any((rec.get(k) not in (None, "", "null")) for k in direct_keys)
        if isinstance(doc, dict):
            has_direct = has_direct or any(
                (v not in (None, "", "null")) and str(v).strip().lower() != "null" and k != "customer_reference"
                for k, v in doc.items())
        txt_subjects = subjects_from_text(notes)
        has_direct = has_direct or bool(txt_subjects)
        if isinstance(doc, dict):
            for v in doc.values():
                if isinstance(v, str) and v.strip().lower() not in ("", "null"):
                    has_direct = has_direct or bool(subjects_from_text(v))

        # ---- kind-aware resolution ---------------------------------------
        if state is None:
            if kind == "ACCOUNT_TOMBSTONE":
                state = STATE_PRESENT if has_direct else STATE_REDACTED
                identifiable = has_direct
            elif kind in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"):
                state = STATE_PRESENT if has_direct else STATE_REDACTED
                identifiable = has_direct
            elif kind in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                state = STATE_PRESENT if has_direct else STATE_ANONYMIZED
                identifiable = has_direct
            else:
                state = STATE_PRESENT
                identifiable = has_direct or bool(subjects)
        else:
            identifiable = has_direct or bool(subjects)
            if not has_direct and kind == "USER_PROFILE":
                identifiable = False

        self.observations.append(Observation(
            file_id=fid, system=system, resource_id=rid, kind=kind, state=state,
            identifiable=identifiable, subjects=subjects, t=t or ""))
    # ------------------------------------------------------------- JSON files
    def _parse_json(self, fid: str, path: str, captured: str) -> None:
        doc = json.load(open(path, encoding="utf-8-sig"))
        if "snapshots" in doc:                                # bundle family
            base = doc.get("exported_at") or captured
            for snap in doc["snapshots"]:
                st = snap.get("captured_at") or base
                system = snap.get("data_store") or snap.get("system") or ""
                collection = snap.get("collection") or ""
                self._add_scope(fid, collection or system)
                self._scope_rows(fid, collection or system, len(snap.get("records", [])))
                for rec in snap.get("records", []):
                    rid = rec.get("resource_id") or ""
                    self._emit_from_generic_record(fid, system, rid, rec, st, collection=collection)
        elif "service_exports" in doc:                        # per-service export
            base = doc.get("exported_at") or captured
            for system, colls in doc["service_exports"].items():
                for sub, arr in colls.items():
                    self._add_scope(fid, sub or system)
                    self._scope_rows(fid, sub or system, len(arr or []))
                    for rec in arr:
                        rid = rec.get("resource_id") or ""
                        self._emit_from_generic_record(fid, system, rid, rec, rec.get("observed_at") or base, collection=sub)
        else:                                                 # ledger / targeted family
            base = doc.get("captured_at") or doc.get("exported_at") or captured
            collection = doc.get("collection") or doc.get("source") or ""
            self._add_scope(fid, collection or doc.get("origin") or "")
            self._scope_rows(fid, collection or doc.get("origin") or "", len(doc.get("records", [])))
            for rec in doc.get("records", []):
                rid = rec.get("resource_id") or ""
                self._emit_from_generic_record(
                    fid, rec.get("system") or "", rid, rec,
                    rec.get("recorded_at") or rec.get("observed_at") or base, collection=collection,
                )

    # ------------------------------------------------------------- TXT files
    def _parse_txt(self, fid: str, path: str, captured: str) -> None:
        text = open(path, encoding="utf-8-sig", errors="replace").read()
        for line in text.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if parts and parts[0].startswith("-"):
                parts[0] = parts[0].lstrip("- ").strip()
                parts = [p for p in parts if p]
            if len(parts) >= 5 and parts[0].endswith("Z"):
                t = parts[0].lstrip("- ").strip()
                system, rid, rtype, result = parts[1], parts[2], parts[3], parts[4]
                subj = subjects_from_text(parts[5] if len(parts) > 5 else "")
                state = _normalize_state(result)
                if state is None:
                    continue
                identifiable = state in (STATE_PRESENT, STATE_ACTIVE) and bool(subj)
                if rtype in ("SECURITY_AUDIT_LOG",):
                    state, identifiable = STATE_RETAINED, False
                if rtype == "ANALYTICS_PROFILE" and result == "ANONYMIZED":
                    identifiable = False
                self.observations.append(
                    Observation(
                        file_id=fid, system=system, resource_id=rid,
                        kind=kind_for(system, rtype, rid), state=state,
                        identifiable=identifiable,
                        subjects=subj - _resource_ids(subj),
                        t=t,
                    )
                )

    # ------------------------------------------------------------- LOG files
    _KV_RE = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')

    def _parse_log(self, fid: str, path: str, captured: str) -> None:
        text = open(path, encoding="utf-8-sig", errors="replace").read()
        groups: dict[str, dict] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            self._parse_log_line(fid, captured, line, groups)
        self._resolve_log_groups(fid, captured, groups)

    def _kv(self, text: str) -> dict:
        out = {}
        for m in self._KV_RE.finditer(text):
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else m.group(3)
            out[key.lower()] = val.replace('\\"', '"') if val else val
        return out

    def _extract_trace_key(self, line: str, base: str):
        m = re.search(r"\[(tr-\w+)\]", line)
        if m:
            return m.group(1)
        m = re.search(r"trace_id=(tr-[\w\-]+)", line)
        if m:
            return m.group(1)
        # JSON dialect: "trace_id":"tr-9028396"
        m = re.search(r'"trace_id"\s*:\s*"(tr-[\w\-]+)"', line)
        if m:
            return m.group(1)
        m = re.search(r"trace_id=([\w\-]+\d[\w\-]*)", line)
        if m:
            return m.group(1)
        m = re.search(r"requestId=(?!collector-|resolver-|vault-|notify-|ext-|log-)(\S+?)\s", line + " ")
        if m:
            return m.group(1)
        m = re.search(r"<\d+>1 \S+ \S+ (tr-[\w\-]+)", line)
        if m:
            return m.group(1)
        m = re.search(r"\| (tr-[\w\-]+) \|", line)
        if m:
            return m.group(1)
        return None

    def _parse_log_line(self, fid, captured, line, groups) -> None:
        # fast paths for self-contained "record_lookup" style lines
        if self._selfcontained_line(fid, line):
            return
        trace = self._extract_trace_key(line, captured)
        t = (line.split()[0] if " " in line else captured)
        if not t.endswith("Z"):
            t = captured
        kv = self._kv(line)
        # structured JSON dialect (the JSON payload may follow the ISO stamp)
        if "{" in line:
            try:
                js = json.loads(line[line.index("{"):])
                if isinstance(js, dict):
                    merged = {str(k).lower(): v for k, v in js.items()}
                    merged.update({k: v for k, v in kv.items() if v is not None})
                    kv = merged
            except Exception:
                pass
        # cloud-runtime dialect: inner message carries the real fields
        if kv.get("message"):
            inner = self._kv(str(kv["message"]))
            for k, v in inner.items():
                kv.setdefault(k, v)
        # application-trace dialect: event precedes the colon after the trace tag
        if "event" not in kv:
            m = re.search(r"\]\s*([\w_]+)\s*:", line)
            if m:
                kv["event"] = m.group(1)
        # pipe dialect: event is the 5th '|'-field
        if "event" not in kv and line.count("|") >= 4:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 5 and re.fullmatch(r"\w+", parts[4] or ""):
                kv["event"] = parts[4]
        if trace is None:
            return
        g = groups.setdefault(trace, {"lines": []})
        g["lines"].append({"t": t, "kv": kv, "line": line})

    def _selfcontained_line(self, fid, line) -> bool:
        """Lines that carry system+resource+state on their own (e.g. record_lookup)."""
        for marker in ("event=record_lookup", '"event":"record_lookup"'):
            if marker not in line:
                continue
            kv = self._kv(line)
            seq = re.search(r"seq=(\d+)", line)
            js = None
            if marker.startswith('"event"'):
                try:
                    js = json.loads(line[line.index("{"):])
                except Exception:
                    js = None
            src = js or kv
            t = line.split()[0]
            system = src.get("system") or src.get("service") or ""
            rid = src.get("resource_id") or ""
            state_raw = src.get("result") or ""
            subject = str(src.get("subject_reference") or src.get("subject") or "")
            rtype = src.get("record_type") or ""
            state = _normalize_state(state_raw)
            if state is not None and rid:
                subjects = subjects_from_text(subject)
                identifiable = bool(subjects) and state != STATE_ABSENT
                if rtype == "SECURITY_AUDIT_LOG" or "audit_record" in rid:
                    state, identifiable = STATE_RETAINED, False
                self.observations.append(
                    Observation(file_id=fid, system=system, resource_id=rid,
                                kind=kind_for(system, rtype, rid), state=state,
                                identifiable=identifiable, subjects=subjects, t=t)
                )
            return True
        return False

    def _resolve_log_groups(self, fid, captured, groups) -> None:
        for trace, g in groups.items():
            self._resolve_one_group(fid, captured, g)

    def _resolve_one_group(self, fid, captured, g) -> None:
        lines = g["lines"]
        if not lines:
            return
        # A group spans ONE subject operation: find subject + resource + state.
        subject_tokens: set[str] = set()
        started: dict | None = None
        completions: list[dict] = []          # chronological; earlier wins
        service = ""
        for ln in lines:
            kv = ln["kv"]
            event = (kv.get("event") or "").lower()
            if event.endswith("_started"):
                if not started or ln["t"] <= started["t"]:
                    started = ln
            elif event.endswith("_completed") or event in ("message_pii_scan", "attachment_pii_scan",
                                                          "analytics_identity_scan", "connector_heartbeat",
                                                          "restore_candidate_evaluated", "restoration_failed",
                                                          "deletion_marker_check", "message_read",
                                                          "analytics_profile_read"):
                completions.append(ln)
            if not service:
                for key in ("function", "service"):
                    if key in ln["kv"] and "router" not in kv[key] and "collector" not in kv[key]:
                        service = kv[key]
                        break
                sm = re.match(r"<\d+>1\s+\S+\s+(\S+)\s+tr-", ln["line"])
                if sm and "router" not in sm.group(1):
                    service = sm.group(1)
                if " | " in ln["line"]:
                    parts = [p.strip() for p in ln["line"].split("|")]
                    if len(parts) >= 4 and parts[2] and "router" not in parts[2] and re.fullmatch(r"[\w_]+", parts[2] or ""):
                        service = parts[2]
                    if len(parts) >= 4 and parts[2] and "router" not in parts[2]:
                        service = parts[2]
            for key in ("lookup_key", "subject_key", "match_key", "scan_key", "subject_ref",
                        "subreference", "subject_reference", "customer_email", "customer_reference",
                        "correlation_key", "matched_value", "owner_key", "owner_email"):
                v = ln["kv"].get(key)
                if v and v not in ("null", "None"):
                    subject_tokens |= subjects_from_text(v)
                    if re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", v):
                        subject_tokens.add(v.lower())

        completed = None
        kv = None
        event = ""
        resolved = None
        for ln in completions:
            c_kv = ln["kv"]
            c_event = (c_kv.get("event") or "").lower()
            c_rid = (c_kv.get("resource_id") or "")
            if not c_rid:
                continue
            c_state = self._state_from_event(c_event, c_kv, service, c_rid)
            if c_state is not None:
                completed, kv, event, resolved = ln, c_kv, c_event, c_state
                break
        if completed is None:
            return
        rid = kv.get("resource_id") or ""
        if not service:
            service = _service_from_resource(rid)
        service = _service_from_resource(rid) or service
        t = completed["t"]
        subjects = set(subject_tokens)
        state, identifiable, kind = resolved
        if kind == "SECURITY_AUDIT_LOG":
            state, identifiable = STATE_RETAINED, False
        self.observations.append(
            Observation(file_id=fid, system=service, resource_id=rid, kind=kind,
                        state=state, identifiable=identifiable, subjects=subjects, t=t)
        )

    def _state_from_event(self, event, kv, service, rid):
        """Translate a completed log event into (state, identifiable, kind)."""
        if "profile_lookup" in event:
            rows = kv.get("rows") or (kv.get("http_status") or "")
            found = (rows == "1") or (kv.get("http_status") == "200")
            return (STATE_PRESENT, found, "USER_PROFILE") if found else (STATE_ABSENT, False, "USER_PROFILE")
        if "index_query" in event:
            result = (kv.get("result") or "").lower()
            hits = int(kv.get("total_hits") or "0" if kv.get("total_hits") else 0)
            doc = isinstance(kv.get("qdoc"), dict) if False else None
            if result == "hit" or hits > 0:
                return STATE_PRESENT, True, "SEARCH_INDEX_ENTRY"
            if result == "miss":
                return STATE_ABSENT, False, "SEARCH_INDEX_ENTRY"
            return None
        if "support_ticket_read" in event:
            req = (kv.get("requester_email") or kv.get("requester_name") or
                   kv.get("requester_phone") or "")
            has = req.strip().lower() not in ("", "null", "none")
            return (STATE_PRESENT, has, "SUPPORT_MESSAGE")
        if "message_pii_scan" in event:
            return STATE_PRESENT, True, "SUPPORT_MESSAGE"
        if "message_scan" in event and event.endswith("completed"):
            return STATE_PRESENT, False, "SUPPORT_MESSAGE"
        if "message_read" in event:
            txt = (kv.get("message_text") or "")
            subj = subjects_from_text(txt)
            if "[redacted]" in txt.lower() or is_redacted_text(txt):
                return STATE_REDACTED, False, "SUPPORT_MESSAGE"
            return STATE_PRESENT, bool(subj), "SUPPORT_MESSAGE"
        if "attachment_pii_scan" in event:
            return STATE_PRESENT, True, "SUPPORT_ATTACHMENT"
        if "attachment_scan" in event and event.endswith("completed"):
            return STATE_PRESENT, False, "SUPPORT_ATTACHMENT"
        if "deletion_marker" in event:
            marker = (kv.get("marker_found") or "").lower()
            if marker == "true":
                return STATE_ABSENT, False, "SUPPORT_MESSAGE"
            return STATE_PRESENT, False, "SUPPORT_MESSAGE"
        if "analytics_identity_scan" in event:
            n = int(kv.get("direct_identifiers") or "0")
            return STATE_PRESENT, n > 0, "ANALYTICS_PROFILE"
        if "analytics_profile_read" in event or "analytics_profile_scan" in event:
            has = any(kv.get(k) not in (None, "", "null") for k in ("email", "phone", "email_hash", "customer_reference"))
            has = has or (kv.get("user_id") not in (None, "", "null"))
            n = int(kv.get("direct_identifiers") or "0")
            if n > 0 or has:
                return STATE_PRESENT, True, "ANALYTICS_PROFILE"
            return STATE_ANONYMIZED, False, "ANALYTICS_PROFILE"
        if "contact_lookup" in event or "contact_query" in event:
            rows = (kv.get("rows") or "0").strip()
            try:
                found = int(rows) > 0
            except Exception:
                found = False
            return (STATE_PRESENT, True, "USER_CONTACT") if found else (STATE_ABSENT, False, "USER_CONTACT")
        if "retention_profile_scan" in event:
            return STATE_PRESENT, True, "PRODUCT_TELEMETRY"
        if "connector_config_read" in event or "connector_heartbeat" in event:
            enabled = (kv.get("enabled") or "").lower() == "true"
            return (STATE_ACTIVE, True, "DATA_FLOW") if enabled else (STATE_DISABLED, False, "DATA_FLOW")
        if "restore_policy_read" in event or "restore_policy_check" in event:
            allowed = (kv.get("restore_allowed") or "").lower() == "true"
            eligible = (kv.get("eligible") or "").lower()
            block = (kv.get("deletion_block") or "").lower()
            if eligible:
                active = (eligible == "true" and block != "true")
                return (STATE_ACTIVE, True, "BACKUP_ARCHIVE") if active else (STATE_BLOCKED, False, "BACKUP_ARCHIVE")
            return (STATE_ACTIVE, True, "BACKUP_ARCHIVE") if allowed else (STATE_BLOCKED, False, "BACKUP_ARCHIVE")
        if "restore_candidate_evaluated" in event:
            eligible = (kv.get("eligible") or "").lower() == "true"
            block = (kv.get("deletion_block") or "").lower() == "true"
            return (STATE_ACTIVE, True, "BACKUP_ARCHIVE") if (eligible and not block) else (STATE_BLOCKED, False, "BACKUP_ARCHIVE")
        if "audit_record_read" in event:
            rows = kv.get("rows") or ""
            return (STATE_RETAINED, False, "SECURITY_AUDIT_LOG") if rows == "1" else None
        if "export_download_check" in event:
            avail = (kv.get("available") or "").lower() == "true"
            return (STATE_PRESENT, True, "USER_EXPORT") if avail else (STATE_ABSENT, False, "USER_EXPORT")
        return None

    # ------------------------------------------------------------------- PDFs
    def _parse_pdf(self, fid, path, captured) -> None:
        text = _pdf_text(path)
        self._parse_freeform(fid, text, captured)

    def _parse_freeform(self, fid, text, captured):
        subjects = subjects_from_text(text)
        # an explicit resource id written in the document outranks a bare
        # ticket reference (CS-4827 / support_001 -> support_001)
        support_hit = re.search(r"\bsupport_\d+\b", text) or re.search(r"\bCS-\d+\b", text)
        attachment_like = bool(re.search(r"attachment|uploaded|\.pdf\b", text, re.I))
        audit_hit = re.search(r"audit_record_\d+", text)
        order_hits = re.findall(r"ORD-\d+", text)
        retain_until = re.findall(r"[Rr]etain until[^0-9]*((?:\d{1,2} \w+ \d{4}))", text)
        legal_like = bool(order_hits) and bool(retain_until)
        if audit_hit:
            rid = audit_hit.group(0)
            subj = subjects_from_text(text)
            self.observations.append(Observation(
                file_id=fid, system="security_service", resource_id=rid,
                kind="SECURITY_AUDIT_LOG", state=STATE_RETAINED, identifiable=False,
                subjects=subj, t=captured, note="pdf store record"))
        elif support_hit and attachment_like and "attachment" in text.lower():
            rid = support_hit.group(0)
            if rid.startswith("CS-"):
                rid = "support_" + rid.split("-")[1]
            self.observations.append(Observation(
                file_id=fid, system="support_platform", resource_id=rid,
                kind="SUPPORT_ATTACHMENT", state=STATE_PRESENT, identifiable=True,
                subjects=subjects, t=captured, note="pdf ups"))
        elif legal_like:
            return  # retained legal records require no action
        else:
            return

    # ------------------------------------------------------------------- PNGs
    def _parse_png(self, fid, row, captured) -> None:
        pass  # populated from the vision facts cache by the pipeline

    def _emit_image_facts(self, fact) -> None:
        observations = fact.get("observations") or []
        for o in observations:
            state = _normalize_state(o.get("state") or "")
            if state is None:
                continue
            subjects = set(o.get("subjects") or [])
            identifiable = bool(subjects) and state not in (STATE_ABSENT,)
            if o.get("kind") == "SECURITY_AUDIT_LOG":
                state, identifiable = STATE_RETAINED, False
            self.observations.append(Observation(
                file_id=fact["file_id"], system=o.get("system") or "",
                resource_id=o.get("resource_id") or "", kind=o.get("kind") or "",
                state=state, identifiable=identifiable, subjects=subjects,
                t=fact.get("captured_at") or "", captured_at=fact.get("captured_at") or "", note="image fact"))


# --------------------------------------------------------------------- helpers
_GUESS_COLS = ["resource_id"] + ["c%d" % i for i in range(1, 14)]


def _split_sql_values(payload: str) -> list[str]:
    out, depth, cur, in_str = [], 0, "", False
    i = 0
    while i < len(payload):
        ch = payload[i]
        if in_str:
            if ch == "'":
                if i + 1 < len(payload) and payload[i + 1] == "'":
                    cur += "'"
                    i += 2
                    continue
                in_str = False
                cur += ch
            else:
                cur += ch
        else:
            if ch == "'":
                in_str = True
                cur += ch
            elif ch == "," and depth == 0:
                out.append(cur.strip())
                cur = ""
            elif ch in "([{":
                depth += 1
                cur += ch
            elif ch in ")]}":
                depth -= 1
                cur += ch
            else:
                cur += ch
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return [_unquote(v) for v in out]


def _unquote(v):
    if v is None:
        return None
    v = v.strip()
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1].replace("''", "'")
    if v.upper() == "NULL":
        return None
    return v


def _system_from_table(table: str) -> str:
    tl = (table or "").lower()
    if "account" in tl:
        return "account_service"
    if "search" in tl:
        return "search_service"
    if "analytics" in tl:
        return "analytics_platform"
    if "support" in tl:
        return "support_platform"
    if "connector" in tl:
        return "integration_service"
    if "backup" in tl:
        return "backup_service"
    if "security" in tl:
        return "security_service"
    if "export" in tl:
        return "export_service"
    if "customer_data" in tl:
        return "account_service"
    return ""


def _service_from_resource(rid: str) -> str:
    p = rid.split("_", 1)[0]
    return {
        "account": "account_service",
        "search": "search_service",
        "analytics": "analytics_platform",
        "support": "support_platform",
        "data": "integration_service",
        "backup": "backup_service",
        "audit": "security_service",
        "export": "export_service",
        "tombstone": "identity_service",
        "marketing": "marketing_platform",
        "cache": "cache_service",
        "email": "notification_service",
        "object": "object_storage",
        "legal": "legal_service",
    }.get(p, "")


def _normalize_state(raw: str) -> str | None:
    r = (raw or "").strip().upper()
    if r in ("FOUND", "PRESENY", "PRESENT", "RECORD", "200"):
        return STATE_PRESENT
    if r in ("NOT_FOUND", "ABSENT", "RECORDS=0", "404"):
        return STATE_ABSENT
    if r == "REDACTED":
        return STATE_REDACTED
    if r == "ANONYMIZED":
        return STATE_ANONYMIZED
    if r == "IDENTIFIABLE":
        return STATE_PRESENT
    if r == "ACTIVE":
        return STATE_ACTIVE
    if r == "DISABLED":
        return STATE_DISABLED
    if r == "BLOCKED":
        return STATE_BLOCKED
    return None


def is_redacted_text(txt: str) -> bool:
    t = (txt or "").lower()
    if "[redacted]" in t:
        return True
    if "redacted" in t and "@" not in (txt or ""):
        return True
    return False


def _resource_ids(subj: set[str]) -> set[str]:
    return {s for s in subj if re.fullmatch(r"[a-z]+_\d+", s) and not s.startswith(("p:", "user_"))}


def _pdf_text(path: str) -> str:
    try:
        from pypdf import PdfReader
    except Exception:
        return ""
    try:
        reader = PdfReader(path)
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        return ""
