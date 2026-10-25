# Evaluation Report

## Scope and provenance

This report covers the final run attempts against participant-facing data. A
bounded genuine sample run was attempted through the configured OpenAI
Responses API, but all 32 calls failed at the provider transport boundary and
returned no intent classifications. The OCR backend remained blocked and no
validated intent cache was available. The structured diagnostic below bypasses
intent and is reported only to expose pipeline failures; it is not presented
as model performance or as a submission candidate.

Commands executed from the repository root:

```powershell
python -m pytest -q --ignore=tests/test_multimodal_ingestion.py
python code\main.py inspect --json
python code\main.py inspect --sample --json
python code\main.py run-audit --sample --mode structured --diagnostic --output artifacts\diagnostic-sample-predictions.csv --json
python code\evaluation\main.py --predictions artifacts\diagnostic-sample-predictions.csv --reference dataset\sample_output.csv --requests dataset\sample_deletion_requests.csv --json
python code\main.py run-audit --mode structured --diagnostic --json
python code\main.py run-audit --sample --mode structured --live --usage-report artifacts\final-sample-live-usage.json --json
```

## Metrics

The safe non-OCR suite passed **292 tests**. Both dataset inspections were
valid with zero errors and warnings: 32 sample requests and 518 evaluation
requests, with all expected supporting-file counts.

The genuine sample attempt produced no prediction rows: coverage was **0/32**,
all 32 cases were unresolved at intent authorization, and status accuracy over
the required 32-case denominator was therefore **0%**. Step, field, and
sequence metrics were not computed because no prediction file was produced.
This is a provider-failure result, not a measurement of the downstream policy
pipeline. Actual attempts and unknown usage are recorded in `usage_report.md`.

The intent-bypassing structured sample diagnostic resolved 4 of 32 cases and
left 28 unresolved. Its evaluator result, with missing predictions retained in
all denominators, was:

| Metric | Diagnostic result |
| --- | ---: |
| Prediction coverage / contract-valid cases | 4/32 (12.5%) |
| Case-status accuracy | 4/32 (12.5%) |
| Exact-row accuracy | 0/32 (0%) |
| Step precision | 68.0% |
| Step recall | 8.81% |
| Step F1 | 15.60% |
| Step-field accuracy | 126/1379 (9.14%) |
| Sequence accuracy | 0/32 (0%) |
| Unresolved cases | 28/32 |

These figures are deliberately labeled diagnostic because intent was bypassed.
No metric was computed only over the four easy/resolved cases.

The final full structured diagnostic resolved 84 cases as `INCOMPLETE` and left
**434/518 unresolved**. It produced no `COMPLETE` rows because incomplete OCR
coverage or other unresolved relevant evidence prevented a complete-state
claim. Major overlapping root-cause counts were: security-retention facts
(180 cases), deferred/global coverage (153), support ownership/context (159),
same-resource account conflicts (105), process state (67), unresolved category
(58), and retained-record repair gaps that the output vocabulary cannot express
(13). The full JSON diagnostic is retained at
`artifacts/final-full-diagnostic.json`.

## Additional participant-created cases

Five independent cases in `code/evaluation/fixtures.py` remain separate from
prediction inputs:

1. Non-deletion access request -> `NOT_APPLICABLE` and no steps.
2. Evidence-backed absence -> `COMPLETE` with an absence verification.
3. Tombstone PII plus a retained security ledger -> redact the tombstone and
   preserve the ledger.
4. Enabled connector -> report, disable, and verify the data flow.
5. Restorable backup -> report, block, and verify the restore path.

Evaluator mutation tests cover wrong status, missing/extra/duplicate/reordered
steps, wrong evidence and numbering, malformed JSON, missing/extra/duplicate
cases, invalid field types, and non-empty `NOT_APPLICABLE` output.

## Failures found and improvements made

- Removed the unsafe `RETAIN`/unknown-action fallback to `DELETE_RECORD` and
  separated retained-record verification from restore blocking.
- Hardened root `output.csv` replacement: only a complete, non-diagnostic,
  exact-ID, sorted 518-case run can replace it. Diagnostic artifacts must live
  under `artifacts/` and contain `diagnostic` in the filename; writes remain
  atomic and preserve an existing file on failure.
- Replaced permissive citation extraction with exact participant-visible ID
  validation and selected proof from the applicable physical copy. Future
  absence evidence and unverified claims cannot prove state; all underlying
  proof references remain internal.
- Added strict, versioned intent-cache validation bound to request-text digest,
  prompt provenance, and an in-request supporting quote. Malformed and stale
  caches fail closed.
- Made usage JSON lossless for decimal cost, persistent per attempt, and able to
  create its parent directory without inventing unknown usage or price values.
- Added grounded control dependencies to the execution graph, cycle detection,
  and kept dependency order separate from canonical output presentation.
- Parsed native-text PDFs without OCR, propagated nested retention fields,
  preserved SQL row `origin_system`, decoded structured record JSON, prevented
  operational claims from becoming stored records, and separated process
  configurations from record-policy evaluation.
- Prevented resource-less scoped inventories from materializing as false
  `unspecified_resource` records, reducing full unresolved cases from 440 to
  434 without weakening evidence checks.

## Remaining limitations

- Eleven PNG files still require the OCR backend whose outbound Microsoft
  telemetry connection triggered approval review. It was not retried or routed
  around.
- Genuine sample predictions remain blocked because the authorized provider
  attempt returned 32 transport failures; a validated cache is still absent.
- Structured diagnostics expose unresolved support ownership, retention,
  process-state, category, copy-conflict, and coverage questions. The pipeline
  now fails closed instead of emitting an incomplete remediation plan as
  exhaustive.
- Hidden full-dataset accuracy is not measurable from participant-facing data.
- The usage report records the failed genuine sample attempts and explicitly
  states that no final 518-case run or `output.csv` was produced.
