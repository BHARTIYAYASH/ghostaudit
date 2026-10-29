# Copyright (c) 2026 Yash K. All rights reserved.
"""GhostAudit - CLI.

Run from the repository:

    python code/main.py --validate     # compare against dataset/sample_output.csv
    python main.py --run               # full 518-case run -> root output.csv

Options:
    --dataset DIR   dataset directory (default: <repo>/dataset)
    --out PATH      output csv path for --run (default: <repo>/output.csv)
    --case ID       restrict a run/validate to one case_id (debugging)
    --quiet         silence progress output
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys


def _repo_root() -> str:
    # code/main.py -> code -> repository root
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _serialize_steps(steps: list[dict]) -> str:
    return json.dumps(steps, ensure_ascii=False, sort_keys=True)


def _write_output(path: str, results: dict, rows: list[dict]) -> int:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        w.writerow(["case_id", "deletion_status", "steps_json"])
        def _case_key(row: dict):
            m = re.search(r"(\d+)", row["case_id"] or "")
            return (int(m.group(1)) if m else 0, row["case_id"])

        for row in sorted(rows, key=_case_key):
            cid = row["case_id"]
            status, steps = results[cid]
            w.writerow([cid, status, _serialize_steps(steps)])
    return len(results)


def _load_gold(path: str) -> dict[str, tuple[str, list]]:
    gold: dict[str, tuple[str, list]] = {}
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            gold[row["case_id"]] = (row["deletion_status"],
                                    json.loads(row["steps_json"] or "[]"))
    return gold


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GhostAudit deletion-audit agent")
    ap.add_argument("--validate", action="store_true",
                    help="run the 32 sample cases and compare with sample_output.csv")
    ap.add_argument("--run", action="store_true",
                    help="run the full 518-case dataset and write output.csv")
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--case", default=None,
                    help="restrict to a single case_id (debugging)")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--quiet", action="store_true",
                    help="silence progress output")
    args = ap.parse_args(argv)
    quiet = args.quiet

    if not (args.validate or args.run):
        ap.error("choose --validate or --run")

    root = _repo_root()
    dataset = args.dataset or os.path.join(root, "dataset")

    from ghostaudit.pipeline import Pipeline

    pipe = Pipeline(dataset, verbose=args.verbose)

    def _select(rows):
        if args.case:
            rows = [r for r in rows if r["case_id"] == args.case]
        return rows

    if args.run:
        rows = _select(pipe.corpus.requests)
        results = pipe.run(rows)
        out_path = args.out or os.path.join(root, "output.csv")
        n = _write_output(out_path, results, rows)
        from collections import Counter
        tally = Counter(status for status, _ in results.values())
        if not quiet:
            print(f"wrote {out_path} ({n} rows) " +
                  ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))
        return 0

    # ---------------------------------------------------------------- validate
    gold_rows = _select(pipe.corpus.samples)
    # the gold sample cases belong to the same global cluster space; run the
    # pipeline over the full request set plus the samples (their band-op
    # pairing needs the companion cases that share their reported_at)
    rows = _select(pipe.corpus.requests) + gold_rows
    results = pipe.run(rows)
    gold = _load_gold(os.path.join(dataset, "sample_output.csv"))
    out_path = args.out or os.path.join(root, "dataset", "output.csv")
    _write_output(out_path, results, gold_rows)
    good = 0
    for row in sorted(gold_rows, key=lambda r: r["case_id"]):
        cid = row["case_id"]
        status, steps = results[cid]
        g_status, g_steps = gold.get(cid, ("MISSING", []))
        if status == g_status and steps == g_steps:
            good += 1
            continue
        if not quiet:
            print(f"MISMATCH {cid}: got={status} want={g_status} "
                  f"steps={len(steps)}/{len(g_steps)}")
        if args.verbose and not quiet:
            if status != g_status:
                print(f"  status: {status} != {g_status}")
            for i in range(max(len(steps), len(g_steps))):
                a = steps[i] if i < len(steps) else None
                b = g_steps[i] if i < len(g_steps) else None
                if a != b:
                    print(f"  step {i + 1}: got={json.dumps(a, sort_keys=True)}")
                    print(f"            want={json.dumps(b, sort_keys=True)}")
                    break
        if not quiet:
            print(f"score {good}/{len(gold_rows)}")
    if not quiet:
        print(f"VALIDATION {good}/{len(gold_rows)}")
    return 0 if good == len(gold_rows) else 1


if __name__ == "__main__":
    sys.exit(main())
