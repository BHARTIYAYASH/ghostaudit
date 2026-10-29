"""GhostAudit — AI-powered deletion-audit agent for "Ghost Data Still Exists".

Architecture (evidence-knowledge-graph):

    corpus         -> identity graph (current + historical identifiers)
    parse_evidence -> normalized observations from every evidence family
    activity       -> global activity stream -> observations + workflow ops
    binding        -> binds resources to subjects (identifier graph + workflow windows)
    policy         -> deletion_rules.csv -> required treatment per resource kind
    decide         -> verdict (COMPLETE / INCOMPLETE / NOT_APPLICABLE) + ordered steps
    pipeline       -> orchestrates everything and writes output.csv

Only participant-facing files under ``dataset/`` are read. No golden labels,
no organizer-only files, no case-family shortcuts are used.
"""

__version__ = "1.0.0"
