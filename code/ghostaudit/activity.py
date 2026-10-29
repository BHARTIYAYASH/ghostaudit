"""Global activity stream -> claims, workflow ops, and direct links."""

from __future__ import annotations

import csv
import os
import re

from .parse_evidence import Observation, WorkflowOp, subjects_from_text, _dt

WORKFLOW_SOURCE = "deletion_worker"

_OP_KIND = {
    "DELETE_RECORD": "record",
    "REDACT_RECORD": "record",
    "ANONYMIZE_RECORD": "record",
    "DISABLE_DATA_FLOW": "flow",
    "BLOCK_RESTORE": "backup",
    "CHECK_DATA_FLOW": "flow",
    "CHECK_RESTORE_ACCESS": "backup",
}


class ActivityIndex:
    def __init__(self, corpus) -> None:
        self.ops: list[WorkflowOp] = []
        self.observations: list[Observation] = []
        self.links: list[dict] = []           # LINK_RESOURCE_IDENTITY rows
        self.classifies: list[dict] = []      # CLASSIFY_REQUEST rows
        self._build(corpus)

    def _build(self, corpus) -> None:
        for row in corpus.activity:
            et = row.get("event_type", "")
            op = WorkflowOp(
                activity_id=row.get("activity_id", ""),
                event_time=row.get("event_time", ""),
                op=et,
                source_system=row.get("source_system", ""),
                target_system=row.get("target_system", ""),
                resource_id=row.get("resource_id", ""),
                reported_result=row.get("reported_result", ""),
                details=row.get("details", ""),
                subjects=subjects_from_text(row.get("details", ""))
                | subjects_from_text(row.get("resource_id", "")),
            )
            self.ops.append(op)
            if et == "LINK_RESOURCE_IDENTITY":
                self.links.append(op)
            elif et == "CLASSIFY_REQUEST":
                self.classifies.append(op)
            elif et in ("ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"):
                # claims that a policy action completed — never trusted alone
                obs_kind = {
                    "ANONYMIZE_RECORD": "ANALYTICS_PROFILE",
                    "REDACT_RECORD": "SUPPORT_MESSAGE",
                    "DISABLE_DATA_FLOW": "DATA_FLOW",
                    "BLOCK_RESTORE": "BACKUP_ARCHIVE",
                }[et]
                state = {"ANALYTICS_PROFILE": "ANONYMIZED", "SUPPORT_MESSAGE": "REDACTED",
                         "DATA_FLOW": "DISABLED", "BACKUP_ARCHIVE": "BLOCKED"}[obs_kind]
                self.observations.append(Observation(
                    file_id=op.activity_id, system=row.get("target_system", ""),
                    resource_id=row.get("resource_id", ""), kind=obs_kind, state=state,
                    identifiable=False, subjects=set(op.subjects), t=op.event_time, claim=True))

    # ------------------------------------------------------------------ query
    def ops_in_window(self, start, end) -> list[WorkflowOp]:
        out = []
        for op in self.ops:
            dt = op.dt
            if dt is None:
                continue
            if start <= dt <= end:
                out.append(op)
        return out

    def workflow_ops_in_window(self, start, end) -> list[WorkflowOp]:
        return [op for op in self.ops_in_window(start, end) if op.source_system == WORKFLOW_SOURCE]

    def links_for_resource(self, rid: str) -> list[WorkflowOp]:
        return [ln for ln in self.links if ln.resource_id == rid]

    def classified_resources(self) -> set[str]:
        return {c.resource_id for c in self.classifies}
