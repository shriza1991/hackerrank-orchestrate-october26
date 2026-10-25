# Final Run Usage Report

## Outcome

No successful genuine 518-case run was produced, and root `output.csv` does
not exist. This report records the actual Task 13 attempt rather than
fabricating final-run usage.

## Attempt provenance

- Pipeline command: `run-audit --sample --mode structured --live`
- Scope: 32 public sample requests
- Diagnostic bypass: disabled
- Provider: OpenAI Responses API
- Requested model: `gpt-6-luna`
- Usage source: `artifacts/final-sample-live-usage.json`
- Result: all requests failed at the provider transport boundary; no parsed
  intent classification was returned and investigation remained unauthorized.

## Actual accounting

| Metric | Overall | OpenAI / gpt-6-luna |
| --- | ---: | ---: |
| Logical requests | 32 | 32 |
| New API attempts | 32 | 32 |
| Successful calls | 0 | 0 |
| Failed attempts | 32 | 32 |
| Cache hits | 0 | 0 |
| Known input tokens | 0 | 0 |
| Known output tokens | 0 | 0 |
| Attempts with unknown usage | 32 | 32 |
| Reused input/output tokens | 0 / 0 | 0 / 0 |
| Estimated cost | unavailable | unavailable |

The provider supplied request IDs but no token counts. Therefore token totals,
per-request averages, and cost are unknown—not zero. Configured reference
prices were not applied because no attempt returned billable usage metadata.
The earlier configuration-only attempt made zero API calls because
`GHOST_AUDIT_MODEL` was unset.

No full-dataset model attempt was made after the uniform sample failure, which
avoided repeating 518 calls that could not authorize any case. No OCR call was
made, and no cached usage was reused.
