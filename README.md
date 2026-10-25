# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Tested Windows PowerShell setup from the extracted submission directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python code\main.py inspect --dataset .\dataset --json
python -m pytest -q --ignore=tests/test_multimodal_ingestion.py
```

Place the supplied `dataset` directory at `.\dataset`, or pass its location with
`--dataset`. Native-text PDF extraction requires PyMuPDF, which is included in
`requirements.txt`. Image OCR is optional and is not part of the verified safe
run because the RapidOCR backend's outbound telemetry connection remains
blocked for approval.

For a genuine run, configure environment variables without committing values:

```powershell
$env:GHOST_AUDIT_API_KEY = '<provider key>' # OPENAI_API_KEY is also accepted
$env:GHOST_AUDIT_MODEL = '<exact Responses API model id>'
$env:GHOST_AUDIT_INPUT_PRICE_PER_MILLION = '<optional decimal>'
$env:GHOST_AUDIT_OUTPUT_PRICE_PER_MILLION = '<optional decimal>'
python code\main.py model-smoke
```

For Gemini, install the included `google-genai` dependency and use the official
SDK transport rather than an OpenAI-compatible endpoint:

```powershell
$env:GHOST_AUDIT_PROVIDER = 'gemini'
$env:GEMINI_API_KEY = '<Gemini API key>'
$env:GHOST_AUDIT_MODEL = '<exact Gemini model id>'
python code\main.py classify-intent --text 'Please delete my account.' --live --report
```

Run the 32 public requests with live intent classification:

```powershell
python code\main.py run-audit --sample --mode structured --live --output artifacts\sample-predictions.csv --usage-report artifacts\sample-usage.json --json
python code\evaluation\main.py --predictions artifacts\sample-predictions.csv --reference dataset\sample_output.csv --requests dataset\sample_deletion_requests.csv --json
```

Alternatively, provide a strict versioned cache using `--intent-cache
<path.json>`. Cache entries are bound to the current request-text SHA-256,
prompt version, provider/model provenance, and a supporting quote contained in
the request text; malformed or stale caches fail closed.

The final command is allowed to replace root `output.csv` only when every one
of the 518 cases resolves without diagnostic bypass and passes exact ID,
ordering, schema, citation, and step validation:

```powershell
python code\main.py run-audit --mode structured --live --output .\output.csv --usage-report artifacts\final-usage.json --json
```

Use `--mode all` only after the OCR dependency/approval issue is resolved.
Diagnostic inspection uses `--diagnostic`, can write only clearly named files
under `artifacts\`, and can never replace root `output.csv`. The blank template
at `dataset\output.csv` is not a prediction file.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.

---

## Foundation and Setup (Task 1)

### Requirements

- Python 3.11 or newer
- Dependencies: `pydantic>=2.0.0`, `pytest>=8.0.0`

Install dependencies:

```bash
pip install -r requirements.txt
```

### Dataset Inspection CLI

To validate and inspect all participant-facing files and verify against the expected challenge dataset counts:

```bash
# Inspect the 518 evaluation requests and dataset files
python code/main.py inspect

# Inspect the 32 sample requests
python code/main.py inspect --sample

# Output machine-readable JSON summary
python code/main.py inspect --json

# Override dataset location
python code/main.py inspect --dataset path/to/dataset
```

### Running Tests

Execute the test suite with pytest:

```bash
python -m pytest -v
```

### Task 1 validation guarantees

- Required identifiers and request text reject empty or whitespace-only values.
  Optional phone/hash values and cleared historical values remain allowed.
- CSV loading rejects duplicate/blank headers and malformed quoting, preserves
  physical source line numbers, and excludes duplicate primary IDs from records.
- Input and intermediate timestamps reject naive values and normalize to UTC.
  Timestamp formatting preserves fractional seconds and future retention dates
  remain valid policy metadata.
- Output rows enforce status, phase, numbering, ordering, and citation rules at
  construction and again before CSV serialization. Nested list mutation cannot
  bypass export validation. Step numbers must be actual integers.
- Regression tests also check that all 32 official sample answers remain compatible
  with these structural contracts. This is not a prediction-accuracy measurement.

Task 1 performs inspection and contract validation only. It makes no model calls,
does not generate predictions, and does not modify the supplied dataset.

---

## Evaluation Framework (Task 2)

Evaluate an explicit prediction file against the 32 public reference answers:

```bash
python code/evaluation/main.py --predictions path/to/predictions.csv
```

The reference and request defaults resolve from the repository regardless of
the current working directory. They can be overridden, and a detailed Markdown
report or machine-readable JSON can be requested:

```bash
python code/evaluation/main.py \
  --predictions path/to/predictions.csv \
  --reference dataset/sample_output.csv \
  --requests dataset/sample_deletion_requests.csv \
  --report code/evaluation/evaluation_report.md \
  --json
```

The evaluator reports status and exact-row accuracy, multiset step precision /
recall / F1, positional field accuracy, sequence accuracy, coverage, contract
violations, and per-case diagnostics. It retains raw JSON for comparison and
does not sort, renumber, coerce, fill, or deduplicate malformed predictions.
Reference answers are loaded only by the independent `evaluation` package;
`ghost_audit` does not import evaluator code.

Exit code `0` means evaluation completed and prediction coverage/contract are
valid, even if accuracy is below 100%. Exit `1` means prediction contract or
coverage failed. Exit `2` means an input is unusable, including a malformed
reference. No API key, model, network access, or prediction pipeline is needed.

---

## Model Gateway and Usage Tracking (Task 3)

Task 3 adds a provider-neutral structured-call gateway under
`code/ghost_audit/llm/` and one OpenAI Responses API transport. Imports,
inspection, evaluation, and offline tests do not require credentials.

### Configuration

Copy `.env.example` as a reference and set variables in the process environment;
the project deliberately does not load or commit `.env` files.

| Variable | Meaning | Default |
| --- | --- | --- |
| `GHOST_AUDIT_API_KEY` | Provider credential (`OPENAI_API_KEY` is a fallback) | unset |
| `GHOST_AUDIT_MODEL` | Exact requested model identifier | unset |
| `GHOST_AUDIT_API_BASE_URL` | OpenAI-compatible API root | `https://api.openai.com/v1` |
| `GHOST_AUDIT_PROVIDER` | Provider label used in records | `openai` |
| `GHOST_AUDIT_REQUEST_TIMEOUT` | Per-attempt timeout in seconds | `30` |
| `GHOST_AUDIT_MAX_ATTEMPTS` | Total attempts, bounded from 1 to 10 | `3` |
| `GHOST_AUDIT_INITIAL_BACKOFF` | Initial exponential backoff seconds | `0.5` |
| `GHOST_AUDIT_MAX_BACKOFF` | Maximum permitted retry delay | `8` |
| `GHOST_AUDIT_CACHE_ENABLED` | Enable validated-response caching | `true` |
| `GHOST_AUDIT_CACHE_DIR` | Ignored cache location | `.cache/ghost_audit_llm` |
| `GHOST_AUDIT_INPUT_PRICE_PER_MILLION` | Optional input-token price estimate | unavailable |
| `GHOST_AUDIT_OUTPUT_PRICE_PER_MILLION` | Optional output-token price estimate | unavailable |
| `GHOST_AUDIT_MAX_OUTPUT_TOKENS` | Optional positive output limit | unset |

Prices are never guessed. Both prices and provider token totals must be present
for cost estimates; otherwise cost is reported as unavailable.

### Synthetic smoke command

An offline check is the default and makes no network request:

```bash
python code/main.py model-smoke
```

A potentially paid synthetic request requires explicit authorization:

```bash
python code/main.py model-smoke --live
python code/main.py model-smoke --live --report
```

The report flag writes development-only accounting to the ignored
`artifacts/model-smoke-usage.md`; it never overwrites the final
`code/evaluation/usage_report.md`. Repeating an identical successful request
uses the cache when enabled and records zero new API calls for that cache hit.

### Validation, retries, cache, and accounting

- The adapter requests strict JSON Schema output and locally revalidates the
  raw response with Pydantic. Invalid JSON, missing/extra fields, wrong types,
  empty output, refusals, and truncation are failures and are never repaired.
- Authentication, configuration, and ordinary client failures are not retried.
  Timeouts, connections, temporary rate limits, and server failures use bounded
  exponential backoff. Provider `Retry-After` is respected only within the
  configured maximum; larger delays stop the call for later handling.
- Cache keys cover endpoint identity, provider/model, task/template, messages,
  schema, generation parameters, and output limit. Credentials are excluded.
  Only validated successes are atomically cached, and cached content is
  revalidated. Corrupt or incompatible entries fail explicitly.
- Every attempt gets a machine-readable usage record. Actual provider token
  totals are retained for successful and schema-invalid responses and retries;
  unavailable usage remains unknown. Cached/reasoning token breakdowns remain
  subsets of provider totals and are not double-counted. Cache-reused logical
  tokens are reported separately from newly billed tokens.

The transport follows the official OpenAI guidance for
[Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses)
and [API error handling](https://developers.openai.com/api/docs/guides/error-codes).
Task 3 contains no intent classifier, evidence processing, deletion decisions,
or dataset prediction logic.

---

## Request-Intent Classification (Task 4)

Task 4 adds the reusable classifier under `code/ghost_audit/intent/`. Its
versioned prompt is `intent-v1`, and its strict internal decisions are
`DELETION_REQUEST`, `NON_DELETION`, and `AMBIGUOUS`. The result includes a
documented reason code, an exact quote from the supplied text, and a concise
explanation. Call provenance, cache status, and usage references are kept in
separate operational metadata.

The classifier treats multilingual request text as untrusted JSON-delimited
data. It distinguishes direct and polite deletion requests, prior-deletion
follow-ups, export-then-delete requests, non-deletion actions, negation,
hypothetical questions, and unresolved contradictions. Only `request_text`
is supplied as semantic input; case IDs are accounting metadata and workflow
status, email, activity, and sample answers are not included in the prompt.

Inspect the configuration for direct text without making a network call:

```bash
python code/main.py classify-intent --text "Please delete my account."
```

Classify one supplied request after explicitly authorizing a potentially paid
call:

```bash
python code/main.py classify-intent --text "Please delete my account." --live
python code/main.py classify-intent --case case_01 --sample --live
python code/main.py classify-intent --case case_33 --live
```

Use `--dataset path/to/dataset` with case mode to override the dataset path.
The optional `--report` flag writes development-only usage accounting to the
ignored `artifacts/intent-classification-usage.md`; it never writes
`output.csv` or replaces either final evaluation report.

Provider, configuration, schema, and exact-quote validation failures remain
explicit failures. A successful `AMBIGUOUS` result stays unresolved and is
never converted to `NOT_APPLICABLE`. Offline fixtures cover the required
English distinctions, prompt injection, Hindi, Spanish, Portuguese, French,
and Arabic. They test integration with mocked expected outputs, not model
accuracy. Live intent accuracy has not been measured.

Task 4 does not resolve historical identities, inspect evidence, apply policy,
plan remediation, decide final deletion status, or produce predictions.

---

## Historical Identity Resolution (Task 5)

Task 5 adds the deterministic identity-resolution package under `code/ghost_audit/identity/`.
It resolves request emails to stable user identities, recovers historical aliases and identifiers
at the `audit_at` cutoff, and enforces strict temporal and cross-person isolation.

### Features and Guarantees

- **Normalization without Loss:** Whitespace trimming and case-insensitive email matching.
  Original spelling is preserved. Plus-tags, dots, and provider heuristics are never removed
  or inferred. Conservative phone normalization preserves country codes (`+`) and digits
  without equating by suffix. Valid hexadecimal email hashes are normalized to lowercase hex
  without inventing hashing algorithms. Stable user IDs match exactly without prefix collisions.
- **Strict Cutoffs and Temporal Rules:** Evidence is bounded inclusively by `audit_at`.
  Audit events with `event_time > audit_at` and snapshots with `updated_at > audit_at`
  are excluded from pre-cutoff resolution. Older eligible history establishes identity even when
  the snapshot is in the future. Equal-timestamp events are sequenced only when transitions form
  an unambiguous chain; otherwise conflicts are surfaced.
- **Cross-Person Isolation:** Multi-valued indexes prevent cross-person alias overwrites.
  Shared historical emails, recycled emails, and shared phone numbers never merge distinct subjects.
  Multiple plausible candidates remain `AMBIGUOUS`.
- **Rich Provenance and Searchable Identifiers:** Distinguishes current-at-cutoff identifiers
  from historical aliases with half-open validity intervals (`[start, end)`). Provides
  an explicitly cited, deterministically sorted collection of searchable identifiers for subsequent
  evidence retrieval, citing actual `audit_id`s and snapshot row locators without inventing evidence citations.
- **Offline and Model-Free:** Requires no model calls, API keys, or network connectivity.

### Development CLI Commands

Resolve identity for a single case from evaluation requests:

```bash
python code/main.py resolve-identity --case case_37
python code/main.py resolve-identity --case case_01 --sample --json
```

Resolve identity for a direct email and audit cutoff:

```bash
python code/main.py resolve-identity --email "person@example.test" --audit-at "2026-09-01T12:00:00Z" --json
```

Run batch identity resolution summary:

```bash
python code/main.py resolve-identity --batch
python code/main.py resolve-identity --batch --sample
python code/main.py resolve-identity --batch --report
```

CLI Exit Codes:
- `0`: Successful resolution execution (`RESOLVED`, `AMBIGUOUS`, or `UNRESOLVED`).
- `1`: Dataset, file loading, or case-not-found error.
- `2`: Malformed arguments or missing `--audit-at` for direct email mode.

Task 5 does not inspect evidence files, apply deletion policy, plan remediation,
or generate final prediction outputs.

---

## Structured Evidence Ingestion (Task 6)

Task 6 implements deterministic, local structured evidence ingestion under `code/ghost_audit/evidence/`.
It ingests and parses 79 supported participant evidence files into provenance-bearing `EvidenceObservation`s,
and explicitly marks the remaining 15 multimodal files (PDFs and PNG images) as `DEFERRED` to Task 7.

### Supported Evidence Formats

1. **SQL Database Snapshots (24 files):**
   - Executed inside an isolated in-memory SQLite database (`:memory:`).
   - Blocks filesystem attachment (`ATTACH`, `DETACH`) and extension loading.
   - Bounded execution opcode limit protects against runaway execution.
   - Distinguishes primary, regional, failover, and reporting replica tables without collapsing rows.
   - Preserves table names, schemas, row counts, and emits `INVENTORY_SCOPE` observations for empty and populated tables.

2. **JSON Structures (28 files):**
   - Ingests flat record arrays, snapshot bundles, service resource exports, connector configs, and analytics reports.
   - Preserves stable JSON-path locators (e.g. `$.snapshots[0].records[3]`, `$.service_exports.account_service.profile_lookups[0]`).
   - Distinguishes stored records from zero-hit query lookups and process configurations.
   - Preserves explicit `null`, `false`, `0`, and empty string values.

3. **Logs and Shift Handovers (27 files: 26 logs + 1 text):**
   - Ingests structured JSON lines, pipe-delimited streams, bracketed logs, Cloud Runtime exports, syslog RFC-5424, and key-value lines.
   - Tracks physical 1-based line locators (`line:42`).
   - Links split trace start and completion events across common trace IDs without cross-pollinating unrelated requests.
   - Parses shift handover markdown check items (`customer_account_handover_20261001.txt`).
   - Retains unparseable fragments as `RAW_FRAGMENT` observations with diagnostic warnings.

4. **Explicit Multimodal Deferral (15 files: 4 PDFs, 11 PNG images):**
   - Explicitly marked with `IngestionStatus.DEFERRED` and `0` observations.
   - Computed SHA-256 digest recorded for integrity verification.
   - Deferred cleanly without failing structured ingestion.

### Observation Model (`EvidenceObservation`)

Extended with backward-compatible fields:
- `evidence_id`: Manifest file ID reference.
- `source_locator`: Stable JSONPath, SQL table/row, or physical log line locator.
- `capture_time`: Manifest capture timestamp.
- `observation_time`: Event or record content timestamp.
- `system_id`: System or service context.
- `resource_id`: Resource identifier (e.g. `account_005`).
- `observation_type`: `STORED_RECORD`, `LOOKUP_RESULT`, `INVENTORY_SCOPE`, `PROCESS_CONFIG`, `OPERATIONAL_CLAIM`, or `RAW_FRAGMENT`.
- `scope_context`: Store, collection, table, replica role, or trace context.
- `subject_references`: Explicit subject identifiers present in the source.
- `internal_id`: Deterministic observation reference (`obs:<evidence_id>:<index>`).
- `content_digest`: SHA-256 digest of source content.

### Evidence Ingestion CLI Commands

Ingest all manifest evidence files:

```bash
python code/main.py ingest-evidence
```

Ingest a single evidence file:

```bash
python code/main.py ingest-evidence --file evidence_01
python code/main.py ingest-evidence --file evidence_05 --report
```

Output machine-readable JSON summary:

```bash
python code/main.py ingest-evidence --json
```

Save observation artifacts under `artifacts/`:

```bash
python code/main.py ingest-evidence --artifacts-dir artifacts/
```

CLI Exit Codes:
- `0`: Ingestion completed successfully (79 files parsed/partial, 15 files deferred, 0 failed).
- `1`: Ingestion failed (file missing, malformed required input, or unsafe directive).
