# GhostAudit

**An evidence-first deletion-audit agent.**

Your deletion workflow says `COMPLETE`. GhostAudit checks whether that is actually true — and when it isn't, it tells you exactly what is still there, what can bring it back, and the ordered sequence of actions needed to fix it.

```text
$ python code/main.py --run
wrote output.csv (518 rows) COMPLETE=148, INCOMPLETE=360, NOT_APPLICABLE=10
```

---

## The problem

Deleting a person from a modern platform is not one operation. It is dozens.

The primary database is easy. The hard part is everything else: read replicas that drifted, failover nodes nobody queried, search indexes rebuilt from an old snapshot, analytics profiles keyed by a hashed email, support attachments pasted into a ticket, CSV exports sitting in an object store, delivery logs, caches, and backups that are still restorable by anyone with the right console.

On top of that, the workflow status itself is a **claim**. A job can report success while a downstream sync copies the same rows back minutes later, or while a restore from last Tuesday silently re-materializes a profile that was deleted on Monday.

GhostAudit treats every status, activity result, and system message as a claim until an inspected artifact proves the resulting state. It reconstructs what was true at a specific audit timestamp, applies a per-category retention policy, and emits a machine-readable plan.

## What it does

For every deletion request, the agent:

1. **Gates the request.** Access, correction, export, marketing opt-out, and "keep my account" requests are `NOT_APPLICABLE` — no matter how much the rest of the row looks like a deletion.
2. **Resolves the identity.** Current and historical emails, phones, email hashes, and the stable internal user reference are all in scope, because old systems still hold old values.
3. **Reconstructs the true state at `audit_at`.** Only evidence observed *and captured* at or before the audit time counts. Claims are ignored.
4. **Applies policy.** Each data category gets its required treatment: delete, redact, anonymize, retain, disable a data flow, or block a restore. Retained audit records and legal holds survive. Account tombstones keep only the permitted stable reference.
5. **Plans the recovery.** Findings cite evidence. Remediation is ordered so that dangerous flows are stopped before dependent records are touched. Verification covers the final required state.

The result is one row per case:

```csv
case_id,deletion_status,steps_json
```

`deletion_status` is one of `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, and `steps_json` is an ordered array of findings, remediation actions, and verification checks.

## Quick start

Requires **Python 3.10+** (tested on 3.11 and 3.12).

```bash
git clone https://github.com/<you>/ghost-data.git
cd ghost-data

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
# source .venv/bin/activate

pip install -r requirements.txt

# Full run: 518 cases -> output.csv at the repository root
python code/main.py --run

# Compare against the 32 public sample answers
python code/main.py --validate
```

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--dataset DIR` | Run against a different corpus directory |
| `--out PATH` | Write the CSV to a specific path |
| `--case case_42` | Debug a single case |
| `--quiet` / `--verbose` | Silence progress / show mismatch detail |

> **Note on PDF evidence:** the corpus contains four PDF artifacts. Install `pypdf` (it is in `requirements.txt`). Without it, PDFs are skipped and case accuracy drops from `30/32` to `29/32` because one support attachment becomes invisible.

## How it works

GhostAudit is a deterministic five-stage pipeline. There is no model call at inference time.

```text
deletion_requests.csv ─┐
user_identities.csv ───┤   ┌───────────────┐   ┌──────────────┐   ┌──────────┐   ┌──────────────┐
user_audit_log.csv ────┤   │   Evidence    │   │   Identity   │   │  Policy  │   │ Step planner │
system_activity.csv ───┼──▶│  normalizer   │──▶│   binding    │──▶│  engine  │──▶│ + serializer │──▶ output.csv
deletion_rules.csv ────┤   └───────────────┘   └──────────────┘   └──────────┘   └──────────────┘
evidence/** ───────────┘
```

### 1. Evidence normalization

Every artifact is parsed into `Observation` records: one verifiable fact about one resource, from one source.

| Evidence family | Examples | What is extracted |
| --- | --- | --- |
| SQL snapshots | primary, regional, reporting, failover replicas | rows, column mappings, snapshot time, replication drift |
| JSON bundles | exports, records-assurance snapshots | resource state, identifiers, capture time |
| Logs | structured JSON, key-value, plain text | events, trace ids, correlation keys |
| PDFs | support attachments, invoices, handover docs | ticket and resource references, legal holds |
| Screenshots | internal consoles, admin panels | resource state and identifiers (cached facts) |

Each observation records `file_id`, `system`, `resource_id`, `kind`, `state`, whether the subject is directly identifiable, its observation time, and whether it is a **claim** or an **inspection**.

### 2. Identity binding

Identities are linked through grounded channels only:

- exact match on current or historical email, phone, email hash, or `user_NN`;
- explicit `LINK_RESOURCE_IDENTITY` activity rows;
- workflow-operation bands around the reported deletion time, with result-class matching;
- analytics pairing inside a reported-at cluster;
- audit-record trace groups keyed by `subject_ref` / `correlation_key`.

Lookalike decoys (similar names, perturbed addresses) are rejected. Names are never a binding signal; identifiers must match exactly.

### 3. Point-in-time reconstruction

Two clocks matter, and they are deliberately separate:

- **Attribution** can use any evidence, because an identity link does not expire.
- **State** and **citations** require both `observation_time <= audit_at` and `file.captured_at <= audit_at`.

For a given resource, the latest gated non-claim observation wins. Ties break to the earlier capture time, then the smaller file id. This is what stops a later restore from rewriting history for an earlier case.

### 4. Policy evaluation

`deletion_rules.csv` is consumed into a required treatment per category:

| Treatment | Categories |
| --- | --- |
| `DELETE` | profiles, secondary identifiers, search entries, caches, support attachments, exports, marketing profiles, contacts |
| `REDACT` | support messages, account tombstones, email delivery logs |
| `ANONYMIZE` | analytics profiles, product telemetry |
| `RETAIN` | security audit logs, legal holds, backup archives |
| `DISABLE` | active data flows |
| `BLOCK` | restorable backups |

An account tombstone is compliant only when the stable reference remains and every prohibited direct identifier is gone. A record being "present" is not automatically a violation — the category decides whether presence, identifiability, or an active process is the actual problem.

### 5. Step planning

Steps are emitted in the required phase order, with consecutive numbering:

```text
FINDING       REPORT_REMAINING_RECORD → REPORT_EXPOSED_PII → REPORT_ACTIVE_DATA_FLOW → REPORT_RESTORE_RISK
REMEDIATION   DISABLE_DATA_FLOW → BLOCK_RESTORE → DELETE_RECORD → REDACT_RECORD → ANONYMIZE_RECORD
VERIFICATION  VERIFY_RECORD_ABSENT → VERIFY_RECORD_PRESENT → VERIFY_RECORD_REDACTED →
              VERIFY_RECORD_ANONYMIZED → VERIFY_DATA_FLOW_DISABLED → VERIFY_RESTORE_BLOCKED
```

Within a phase, steps sort by operation order, then `system_id`, then `resource_id`, so output is byte-for-byte reproducible.

Example — a compliant case (`case_41`):

```json
[
  {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service",   "resource_id": "account_4051",      "operation": "VERIFY_RECORD_ABSENT",  "state": "ABSENT",    "evidence_id": "evidence_03"},
  {"step_no": 2, "phase": "VERIFICATION", "system_id": "security_service",  "resource_id": "audit_record_7814", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT",   "evidence_id": "evidence_03"},
  {"step_no": 3, "phase": "VERIFICATION", "system_id": "support_platform",  "resource_id": "support_2667",      "operation": "VERIFY_RECORD_REDACTED","state": "REDACTED",  "evidence_id": "evidence_03"},
  {"step_no": 4, "phase": "VERIFICATION", "system_id": "analytics_platform","resource_id": "analytics_6830",    "operation": "VERIFY_RECORD_ANONYMIZED","state": "ANONYMIZED","evidence_id": "evidence_03"},
  {"step_no": 5, "phase": "VERIFICATION", "system_id": "integration_service","resource_id": "data_flow_2901",   "operation": "VERIFY_DATA_FLOW_DISABLED","state": "DISABLED","evidence_id": "evidence_03"},
  {"step_no": 6, "phase": "VERIFICATION", "system_id": "backup_service",    "resource_id": "backup_706",        "operation": "VERIFY_RESTORE_BLOCKED","state": "BLOCKED",  "evidence_id": "evidence_03"}
]
```

Example — a non-deletion request (`case_533`):

```json
[]
```

## Design principles

**Evidence over claims.** Workflow status, activity results, and operator notes are hypotheses. Only inspected artifacts set state.

**Time is a constraint, not metadata.** A perfect finding from next week is not evidence about last week. Every citation is gated by both observation and capture time.

**Deterministic by default.** Same corpus in, same CSV out. No sampling, no temperature, no drift, no per-request cost. The full 518-case run makes zero model calls.

**Policy is data.** Retention behavior lives in `deletion_rules.csv`, not scattered through `if` statements, and is cross-checked against a built-in table so a policy edit cannot be silently ignored.

**Order matters.** Disabling a sync or blocking a restore before deleting the source record is the difference between a fix and a loop. The planner encodes that ordering.

**Explainable output.** Every finding cites a `file_id`. A human reviewer can open the exact artifact and see the same thing the agent saw.

## Results

Measured on the 32-case public sample set, with `pypdf` installed:

| Metric | Result |
| --- | --- |
| Cases with exact status **and** ordered steps | **30 / 32** (93.75%) |
| Deletion-status agreement | **32 / 32** (100%) |
| Sequence accuracy (identical ordered arrays) | **30 / 32** (93.75%) |
| Step-level accuracy | **191 / 193** (98.96%) |
| Pooled field-level accuracy | **1130 / 1146** (98.60%) |

Full-corpus run (518 cases): **148 `COMPLETE`**, **360 `INCOMPLETE`**, **10 `NOT_APPLICABLE`**.

The two residual mismatches (`case_18`, `case_20`) are both missing exactly one post-remediation verification step for a retained audit record. The referenced `audit_record_*` identifiers do not appear in any of the 94 supplied evidence files, so the step cannot be derived from available material without guessing. That is recorded as a corpus coverage gap, not a hidden shortcut — see [`evaluation/evaluation_report.md`](evaluation/evaluation_report.md).

Runtime usage for the full run: **0 model calls, 0 tokens, $0.00**. See [`evaluation/usage_report.md`](evaluation/usage_report.md).

## Repository layout

```text
.
├── code/
│   ├── main.py                  CLI: --run, --validate, --case, --dataset
│   └── ghostaudit/
│       ├── corpus.py            identity graph (current + historical)
│       ├── activity.py          activity stream -> claims, ops, links
│       ├── parse_evidence.py    SQL / JSON / log / PDF / screenshot parsing
│       ├── binding.py           subject -> resource binding channels
│       ├── policy.py            deletion_rules.csv -> required treatment
│       ├── notapplicable.py     request-text gate
│       ├── pipeline.py          orchestration + point-in-time state law
│       ├── decide.py            verdict + canonical step planning
│       └── data/image_facts.json  cached facts for screenshot evidence
├── dataset/                     synthetic corpus (requests, identities, evidence)
├── evaluation/
│   ├── evaluation_report.md     accuracy, fixtures, failures, fixes
│   ├── usage_report.md          token and cost accounting
│   └── fixtures/                three hand-built test cases
├── output.csv                   completed predictions (518 rows)
├── requirements.txt
└── README.md
```

## Output contract

```text
case_id,deletion_status,steps_json
```

- Exactly one row per case in `dataset/deletion_requests.csv`.
- Rows sorted by `case_id`.
- `steps_json` is a JSON array; object-key order and whitespace are ignored, array order is preserved.
- `step_no` starts at `1` and is consecutive.
- Phases appear as `FINDING`, then `REMEDIATION`, then `VERIFICATION`.
- Findings cite a real `evidence_id`; future remediation and post-remediation verification use `""`.
- `NOT_APPLICABLE` always has `steps_json = []`.

## Evaluation

```bash
python code/main.py --validate          # 30/32 on the public sample set
python code/main.py --validate --verbose  # per-step mismatch detail
```

Three additional fixtures run through the real CLI, each isolating one branch:

| Fixture | Scenario | Expected |
| --- | --- | --- |
| `keep_a_statistics` | "Keep the account, only remove me from marketing" | `NOT_APPLICABLE`, `[]` |
| `backup_restore_allowed` | A restorable backup is still active | `INCOMPLETE` → block → verify blocked |
| `tombstone_preserved` | Tombstone already redacted | `COMPLETE` with one redaction verification |

```bash
python code/main.py --run --dataset evaluation/fixtures/backup_restore_allowed --out scratch/out.csv
```

## Limitations

- The request-text gate is keyword-based. It is tuned to the corpus and should be replaced with a classifier before production use.
- Cluster pairing (workflow-op bands, analytics pairing) encodes this platform's workflow shape. A different platform needs its own binding laws.
- Screenshot evidence is read from a precomputed fact cache (`code/ghostaudit/data/image_facts.json`), not from live vision inference.
- Audit-record verification requires the identifier to be discoverable in supplied evidence. If it is not, the agent reports what it can prove rather than inventing a citation.

## Origin

GhostAudit started as an entry for **HackerRank Orchestrate (October 2026)**, whose brief was *"Ghost Data Still Exists."* The submission deadline was missed, so it is published here as a standalone reference implementation.

All people, organizations, identifiers, and records in the bundled corpus are synthetic.
