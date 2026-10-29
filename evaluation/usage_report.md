# Token Usage And Cost Report — GhostAudit

This report summarizes token and cost usage for the final full-dataset run that
produced the final `output.csv`.

## 1. Final Full-Dataset Run (the run that produced `output.csv`)

The final full-dataset run executed the deterministic, rule-based Python pipeline
(no language model was invoked at inference time):

```bash
C:\Users\Yash\AppData\Local\Programs\Python\Python311\python.exe -X utf8 code/main.py --run
```

| Metric | Value |
|---|---|
| Model provider | n/a — deterministic rule-based code path (no provider) |
| Model name | n/a — deterministic rule-based code path (no model) |
| Model calls during final run | **0** |
| Input tokens during final run | **0** |
| Output tokens during final run | **0** |
| Total tokens per request (final run) | **0** |
| Estimated total cost (final run) | **$0.00** |
| Estimated cost per request (final run) | **$0.00** |
| Per-model totals | n/a (single deterministic code path; no models used) |
| Overall totals | n/a (no models used) |

**Honest statement:** the final full-dataset run is pure deterministic Python
logic (evidence parsing -> identity binding -> policy evaluation -> step
planning) and makes **zero model calls** at inference. Consequently every
per-request and total token/cost figure for the run itself is zero, and the
estimated cost per request is $0.00.

## 2. Development Model Usage

The solution was developed using the OpenCode coding agent with model
**`glm-5.3-flash-free`** (free tier).

- **Model provider:** opencode (the development coding-agent harness),
  model id `glm-5.3-flash-free` (free tier).
- Token telemetry for this interactive development session was **not
  instrumented**; therefore precise per-session input/output token counts and
  per-request costs cannot be reported and no fabricated numbers are included.
- Conservative qualitative note: development iterations (pipeline authoring,
  debugging, validation loops) were performed with the above free-tier model;
  no API-key-based or paid inference was used.

## 3. Usage Summary Table

| Category | Model / Provider | Calls | Input Tokens | Output Tokens | Total / Avg Tokens per Request | Est. Cost |
|---|---|---|---|---|---|---|
| Final full-dataset run (produced `output.csv`) | deterministic Python — no model | 0 | 0 | 0 | 0 per request | $0.00 |
| Interactive development session (glm-5.3-flash-free via opencode) | glm-5.3-flash-free / opencode | n/a | n/a (uninstrumented) | n/a (uninstrumented) | n/a (uninstrumented) | n/a (uninstrumented) |

## 4. Conclusion

- Final run: **0 model calls, 0 input tokens, 0 output tokens, $0.00 estimated
  cost** for all 518 cases.
- Development: single model `glm-5.3-flash-free` via opencode (free tier);
  token telemetry uninstrumented, so exact development token/cost numbers are
  unknown and reported as `n/a (uninstrumented)`.
- No model spend was required for this solution.
