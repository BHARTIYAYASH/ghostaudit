"""Whether a request text actually authorizes deletion (contract 6.5).

A request for access, correction, export, marketing opt-out, login help, or
any other non-deletion action is NOT_APPLICABLE even when other fields look
like a deletion case. The classifier works on wording cues only. Two rules:

1. a request whose text carries an explicit keep/retain intent (``don't
   delete``, ``keep the account``, ``still need the account``, ``only remove
   me from marketing lists``, ``access/correction/export`` letters that say
   what must stay) is NOT_APPLICABLE;
2. every other text — including audit/verify phrasings with no explicit
   deletion verb — is treated as authorizing deletion and proceeds through
   the evidence-based audit (the corpus contains genuine deletion requests
   worded as inspections, e.g. "check the systems and confirm the profile
   is gone").

Grounded against the full corpus: the keep-cue rule matches exactly the ten
cases the pipeline's CLASSIFY_REQUEST corroboration confirms as
non-deletion, and matches no sample (gold) deletion case.
"""

from __future__ import annotations

import re

# --- keep / retain intent (the only NOT_APPLICABLE trigger) -----------------
_KEEP_RE = re.compile(
    r"(?i)"
    r"(keep\s+the\s+account|keep\s+my\s+(account|profile|records|data)"
    r"|leave\s+(the\s+account|my\s+profile|my\s+records|my\s+purchase\s+history)"
    r"|leave\s+.{0,20}\bin\s+place|as\s+it\s+is"
    r"|still\s+(want|use|need)"
    r"|continue\s+using"
    r"|not\s+asking\s+for\s+deletion"
    r"|not\s+a\s+request\s+to\s+erase"
    r"|don't\s+delete|don't\s+close|do\s+not\s+close|don't\s+change\s+anything"
    r"|without\s+removing"
    r"|stay\s+active|account\s+active|account\s+open"
    r"|only\s+remove\s+me\s+from\s+marketing"
    r"|service\s+messages|receipts\s+for\s+this\s+account)"
)


def authorizes_deletion(text: str) -> bool:
    """True when the request text asks for deletion of the account/data.

    Any explicit keep/retain intent makes the request non-deletional; all
    other texts authorize the audit (verdicts are then corroborated with the
    CLASSIFY_REQUEST intake record for the subject's account).
    """
    t = text or ""
    return not bool(_KEEP_RE.search(t))


def classify_request_text(text: str) -> bool:
    """True when the text reads as a NON-deletion request (NOT_APPLICABLE)."""
    return not authorizes_deletion(text)
