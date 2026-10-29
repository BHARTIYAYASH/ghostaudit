# Usage And Cost Report — GhostAudit

This report summarizes runtime usage for the full-dataset run that produced
`output.csv`.

## 1. Run

```bash
python code/main.py --run
```

The run executes the deterministic Python pipeline: evidence parsing, identity
binding, policy evaluation, and step planning. No external inference is
performed at any stage.

## 2. Runtime Usage

| Metric | Value |
| --- | --- |
| External inference calls | **0** |
| Input tokens | **0** |
| Output tokens | **0** |
| Total tokens per request | **0** |
| Estimated total cost | **$0.00** |
| Estimated cost per request | **$0.00** |

## 3. Why The Cost Is Zero

State is reconstructed from supplied artifacts with deterministic rules. There
is no sampling, no per-case prompt, and no external API call. The same corpus
always produces the same CSV, which makes the run reproducible and free to
repeat.

## 4. Conclusion

- Full run: **0 inference calls, 0 input tokens, 0 output tokens, $0.00** for
  all 518 cases.
- Every per-request and total cost figure is zero by construction.
- No API keys or paid services are required to run the project.
