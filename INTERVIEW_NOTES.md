# Interview Notes

## Problem and architecture

A workflow status of `COMPLETE` is only a claim. The agent establishes state at
each request's `audit_at` from participant evidence and checks every relevant
copy, retained record, active flow, and restore path.

The implemented pipeline is:

1. Strict intent classification; only a confirmed deletion request authorizes investigation.
2. Current and historical identity resolution to a stable `user_id` plus aliases.
3. Global evidence ingestion and identifier/resource linking with cutoff enforcement.
4. Per-copy state reconstruction using capture time, event time, topology, and scoped inventories.
5. Policy evaluation for `DELETE`, `RETAIN`, `REDACT`, `ANONYMIZE`, and tombstones.
6. Grounded findings, dependency-aware remediation, verification, and validated CSV output.

Unrelated records are isolated by stable identity, aliases, hashes, system and
resource keys, and grounded link provenance. Capture time controls whether an
artifact was available; an embedded event/observation time controls the state
it describes. Later observations resolve historical disagreement, while
equal-time contradictions remain conflicted.

Replica drift is modeled per physical copy. Enabled flows and permitted
restores are separate risks and must be disabled or blocked before dependent
record treatment. `RETAIN` never falls through to deletion. Redaction removes
prohibited direct identifiers while keeping required context; anonymization
requires positive unlinkability evidence; tombstones preserve the stable
subject reference and remove direct identifiers.

Citations must be exact participant-visible evidence, activity, or audit IDs
that establish the reported state for the selected resource/copy before the
cutoff. Missing, stale, future, ownership-only, or unverified workflow claims
produce uncertainty rather than invented output.

## Measured results and limitations

- 292 safe non-OCR tests passed.
- Both dataset inspections passed with zero errors or warnings.
- Structured diagnostic: sample 4 `INCOMPLETE` / 28 unresolved; full 84
  `INCOMPLETE` / 434 unresolved after the final inventory-scope fix.
- Genuine sample attempt: 32/32 provider transport failures, zero successful
  classifications, token usage unknown, and no prediction rows.
- Eleven PNGs remain inaccessible because RapidOCR's outbound telemetry path
  is blocked. Native-text PDFs are parsed without OCR.
- No valid 518-row `output.csv` was produced; fail-closed export protection
  preserved this fact.

## Eight likely questions

1. **Why not trust workflow COMPLETE?** It proves only that an operation was reported, not that every copy is compliant or cannot be recreated.
2. **How are old emails found?** Audit history is replayed to build a cutoff-bounded alias set tied to the stable user reference.
3. **How do you avoid matching another person?** Links require grounded identifiers/resource chains; weak ownership or ambiguous context stays unresolved.
4. **Capture time versus event time?** Capture time determines availability; source-aware event time determines when the observed state held.
5. **How is replica drift handled?** Each physical store/topology is assessed independently; one surviving replica makes deletion incomplete.
6. **How are flows and backups ordered?** Grounded dependencies put flow disablement and restore blocking before treatment of dependent records.
7. **What prevents unsafe remediation?** Exact policy actions are used; unknown actions and missing required retained records remain unresolved, and `RETAIN` cannot map to delete.
8. **Why is there no final CSV?** Genuine intent calls uniformly failed and evidence/OCR gaps left 434 deterministic cases unresolved; the writer correctly rejected partial or diagnostic output.
