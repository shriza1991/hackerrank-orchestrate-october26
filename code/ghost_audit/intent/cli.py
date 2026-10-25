"""Development CLI integration for one request-intent classification."""

from __future__ import annotations

from pathlib import Path

from ghost_audit.config import REPO_ROOT, get_settings
from ghost_audit.intent.service import IntentClassificationService
from ghost_audit.llm.config import get_model_settings
from ghost_audit.llm.errors import GatewayError
from ghost_audit.llm.gateway import ModelGateway
from ghost_audit.llm.transport_factory import create_model_transport
from ghost_audit.llm.usage import UsageTracker
from ghost_audit.loader import DataLoader


def run_intent_classification(
    *, text: str | None, case_id: str | None, sample: bool, dataset: Path | None,
    live: bool, write_report: bool,
) -> int:
    if text is not None and sample:
        print("Intent classification failed: --sample is valid only with --case.")
        return 2
    if text is not None and not text.strip():
        print("Intent classification failed: --text must be nonblank.")
        return 2
    selected_text = text
    selected_case = None
    if case_id is not None:
        settings = get_settings(dataset)
        path = settings.sample_deletion_requests_path if sample else settings.deletion_requests_path
        requests, issues = DataLoader(settings).load_deletion_requests(path)
        errors = [issue for issue in issues if issue.severity == "ERROR"]
        if errors:
            print(f"Intent classification failed: request file has {len(errors)} validation error(s).")
            return 1
        match = next((request for request in requests if request.case_id == case_id), None)
        if match is None:
            print(f"Intent classification failed: case {case_id!r} was not found.")
            return 1
        selected_text = match.request_text
        selected_case = match.case_id
    if not live:
        print("Intent classifier: offline configuration only (no API request made).")
        print(f"Input: {'case ' + selected_case if selected_case else 'direct text'}")
        print("Use --live to authorize one potentially paid classification request.")
        return 0

    tracker = UsageTracker()
    settings = get_model_settings()
    gateway = ModelGateway(settings, create_model_transport(settings), usage=tracker)
    try:
        result = IntentClassificationService(gateway).classify_text(
            selected_text or "", case_id=selected_case, run_id="development-intent-cli"
        )
    except (GatewayError, ValueError) as exc:
        print(f"Intent classification failed: {exc}")
        if write_report:
            path = REPO_ROOT / "artifacts" / "intent-classification-usage.md"
            tracker.write_markdown(path)
            print(f"Development usage report: {path}")
        return 1
    intent, metadata = result.intent, result.metadata
    print(f"Decision: {intent.decision.value}")
    print(f"Reason: {intent.reason_code.value}")
    print(f"Supporting quote: {intent.supporting_quote}")
    print(f"Explanation: {intent.explanation}")
    print(f"Prompt version: {metadata.prompt_version}")
    print(f"Provider/model: {metadata.provider}/{metadata.provider_model or metadata.requested_model}")
    print(f"Cache hit: {metadata.cache_hit}")
    print(f"Attempts: {metadata.attempt_count}")
    print(f"Usage attempt IDs: {', '.join(metadata.usage_attempt_ids)}")
    print(f"Usage summary: {tracker.summary()['overall']}")
    if write_report:
        path = REPO_ROOT / "artifacts" / "intent-classification-usage.md"
        tracker.write_markdown(path)
        print(f"Development usage report: {path}")
    return 0
