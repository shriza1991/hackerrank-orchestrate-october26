# Task 2 Evaluation Framework Report

## Evaluation scope

Task 2 implements an independent evaluator for output CSV files. Its default
reference is `dataset/sample_output.csv`, associated with
`dataset/sample_deletion_requests.csv`. The public reference has been accepted
by structural validation, but no prediction pipeline exists yet. Therefore,
public-sample prediction performance is **not measured**, and hidden
full-dataset accuracy is unknown. No reference-versus-reference check is
presented as solution performance.

## Metric definitions

- **Case-status accuracy** is the number of strict status matches divided by
  all expected cases. Missing, ambiguous duplicate, and unreadable predictions
  receive no credit. Extra IDs invalidate coverage.
- **Exact-row accuracy** requires a matching status, a strict match of the full
  ordered steps array, and a contract-valid prediction row. JSON object-key
  order and whitespace are naturally ignored by parsing; array order, fields,
  and value types remain significant.
- **Step precision, recall, and F1** use micro-aggregated, one-to-one unordered
  multiset matching over the six required fields other than `step_no`.
  Repeated predictions cannot reuse a reference step. If both global step sets
  are empty, precision, recall, and F1 are 1. If predictions are empty while
  expected steps exist, precision and recall are 0. If no steps are expected,
  recall is 1 and precision depends on whether extra steps were predicted.
- **Step-field accuracy** aligns arrays by position and compares all seven
  required fields with strict type-aware equality. Missing and extra steps add
  seven incorrect comparisons. This is order-sensitive; the multiset metrics
  separately measure discovery without order.
- **Sequence accuracy** is the fraction of all expected cases whose complete
  steps array matches in order, including numbers and field values. It remains
  independent of status accuracy.
- **Contract and coverage** report expected and supplied unique IDs, missing,
  extra, and duplicate IDs, contract-valid expected cases, sorted order, and
  JSON/schema error counts. Missing and invalid cases remain in denominators.

## Additional team-created cases

1. `team_001` is a non-deletion access request. Expected output is
   `NOT_APPLICABLE` with `[]`.
2. `team_002` is a completed deletion with an evidence-backed
   `VERIFY_RECORD_ABSENT` step.
3. `team_003` leaves direct identifiers on an account tombstone, requiring a
   finding, redaction, verification of redaction, and verification that a
   required security record remains present.
4. `team_004` has an active connector, requiring a data-flow finding, disable
   action, and disabled-state verification.
5. `team_005` has a backup restore risk, requiring a restore-risk finding,
   block action, and blocked-state verification.

Their complete expected structured outputs and explanations live in
`code/evaluation/fixtures.py`, where code evaluation can inspect them.

## Evaluator correctness tests

Controlled fixture mutations cover wrong status, missing and extra steps, wrong
evidence ID, reordered steps, wrong step number, duplicate steps, missing and
extra cases, duplicate case IDs, malformed JSON, incorrect field types, and an
invalid non-empty `NOT_APPLICABLE` output. Tests also cover perfect metrics,
duplicate-aware matching, empty-step conventions, JSON key/whitespace
invariance, array-order sensitivity, invalid-reference rejection, execution
from another working directory, and prediction/reference package isolation.

The five-case controlled baseline produces 5/5 status, exact-row, and sequence
matches with 100% step and field metrics. Each named mutation is then checked
for the expected metric reduction or contract/coverage failure. These are
evaluator correctness results only, not prediction-system performance.

## Prediction performance

| Scope | Status | Result |
| --- | --- | --- |
| Public 32-case sample | Not measured | No prediction pipeline or prediction file exists |
| Hidden 518-case dataset | Not measurable locally | Canonical hidden answers are unavailable |

## Failures found and improvements made

During implementation, direct strict-mode validation treated valid JSON enum
strings as already-instantiated Python enum objects. Validation was separated
into strict raw primitive checks followed by Task 1 enum and sequence contract
validation. This preserves wrong types without coercion while accepting valid
JSON. A controlled wrong-evidence case also confirmed the intended distinction
between accuracy and contract validity: it lowers comparison metrics but does
not make the CLI fail structurally.

## Limitations

- Evidence IDs are compared by exact equality; semantic citation verification
  belongs to a later task.
- The framework does not evaluate intent classification, identity resolution,
  evidence retrieval, policy reasoning, or generated remediation quality beyond
  comparison with a supplied reference.
- Actual public-sample prediction performance is not measured until a real
  prediction file is supplied.
- Hidden full-dataset accuracy cannot be measured from participant-facing data.
- No usage or cost report was created or modified; that belongs to later runtime
  model-accounting work.
