# Copyright (c) 2026 Yash K. All rights reserved.
"""GhostAudit — evidence-first deletion-audit agent.

Architecture (evidence-knowledge-graph):

    corpus         -> identity graph (current + historical identifiers)
    parse_evidence -> normalized observations from every evidence family
    activity       -> global activity stream -> observations + workflow ops
    binding        -> binds resources to subjects (identifier graph + workflow windows)
    policy         -> deletion_rules.csv -> required treatment per resource kind
    decide         -> verdict (COMPLETE / INCOMPLETE / NOT_APPLICABLE) + ordered steps
    pipeline       -> orchestrates everything and writes output.csv

Only files under ``dataset/`` are read. No golden labels and no hidden
shortcuts are used.
"""

__version__ = "1.0.0"
