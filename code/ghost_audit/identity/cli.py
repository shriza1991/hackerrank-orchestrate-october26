"""CLI handler and formatting utilities for identity resolution."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import Settings, get_settings
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.loader import DataLoader
from ghost_audit.models.intermediate_models import IdentityResolutionResult
from ghost_audit.timestamps import format_iso_timestamp, parse_iso_timestamp


def _json_serial(obj: Any) -> Any:
    """JSON serializer helper for datetime objects."""
    if hasattr(obj, "isoformat"):
        return format_iso_timestamp(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


def format_identity_result_text(result: IdentityResolutionResult, case_id: Optional[str] = None) -> str:
    """Format an IdentityResolutionResult into a human-readable diagnostic report."""
    lines = [
        "=" * 68,
        "IDENTITY RESOLUTION REPORT",
        "=" * 68,
    ]
    if case_id:
        lines.append(f"Case ID                 : {case_id}")
    lines.extend(
        [
            f"Request Email           : {result.request_email or '(not provided)'}",
            f"Normalized Email        : {result.normalized_request_email or '(not provided)'}",
            f"Resolution Status       : {result.resolution_status.value}",
            f"Stable Subject Reference: {result.stable_subject_reference or 'None'}",
            f"Match Method            : {result.match_method or 'None'}",
        ]
    )
    if result.candidates:
        lines.append(f"Candidates ({len(result.candidates)})          : {', '.join(result.candidates)}")

    lines.append("-" * 68)
    lines.append("CURRENT IDENTIFIERS (at audit cutoff):")
    if result.current_identifiers:
        for k, v in sorted(result.current_identifiers.items()):
            lines.append(f"  - {k:<15}: {v}")
    else:
        lines.append("  (none established)")

    lines.append("-" * 68)
    lines.append(f"HISTORICAL IDENTIFIERS ({len(result.historical_identifiers)}):")
    if result.historical_identifiers:
        for h in result.historical_identifiers:
            fld = h.get("field_name", "")
            raw = h.get("raw_value", "")
            v_start = h.get("validity_start")
            v_end = h.get("validity_end")
            start_str = format_iso_timestamp(v_start) if v_start else "unknown"
            end_str = format_iso_timestamp(v_end) if v_end else "cutoff"
            lines.append(f"  - [{fld}] {raw} (valid: {start_str} -> {end_str})")
            sources = h.get("sources", [])
            for s in sources:
                loc = s.get("source_locator", "")
                ctype = s.get("change_type", "")
                lines.append(f"      source: {s.get('source_file')} [{loc}] ({ctype})")
    else:
        lines.append("  (none)")

    lines.append("-" * 68)
    lines.append(f"SEARCHABLE IDENTIFIERS ({len(result.searchable_identifiers)}):")
    if result.searchable_identifiers:
        for ident in result.searchable_identifiers:
            lines.append(f"  * {ident}")
    else:
        lines.append("  (none)")

    lines.append("-" * 68)
    lines.append(f"SUPPORTING AUDIT REFERENCES ({len(result.supporting_references)}):")
    if result.supporting_references:
        lines.append(f"  {', '.join(result.supporting_references)}")
    else:
        lines.append("  (none)")

    if result.warnings:
        lines.append("-" * 68)
        lines.append(f"WARNINGS ({len(result.warnings)}):")
        for w in result.warnings:
            lines.append(f"  [!] {w}")

    if result.conflicts:
        lines.append("-" * 68)
        lines.append(f"CONFLICTS ({len(result.conflicts)}):")
        for c in result.conflicts:
            lines.append(f"  [!] {c}")

    if result.notes:
        lines.append("-" * 68)
        lines.append(f"Notes: {result.notes}")

    lines.append("=" * 68)
    return "\n".join(lines)


def run_identity_resolution(
    case_id: Optional[str] = None,
    email: Optional[str] = None,
    audit_at: Optional[str] = None,
    requested_at: Optional[str] = None,
    sample: bool = False,
    batch: bool = False,
    dataset: Optional[Path] = None,
    json_output: bool = False,
    write_report: bool = False,
) -> int:
    """Execute identity resolution CLI logic."""
    settings = get_settings(dataset)
    loader = DataLoader(settings)

    # Validate inputs
    if not batch and not case_id and not email:
        print("Error: Must specify either --case, --email, or --batch.", file=sys.stderr)
        return 2

    if email and not audit_at:
        print("Error: --audit-at is required when --email is specified.", file=sys.stderr)
        return 2

    if audit_at:
        try:
            parse_iso_timestamp(audit_at)
        except Exception as e:
            print(f"Error: Invalid --audit-at timestamp '{audit_at}': {e}", file=sys.stderr)
            return 2

    if requested_at:
        try:
            parse_iso_timestamp(requested_at)
        except Exception as e:
            print(f"Error: Invalid --requested-at timestamp '{requested_at}': {e}", file=sys.stderr)
            return 2

    # Load only the necessary identity and history CSVs
    identities, id_issues = loader.load_user_identities(settings.user_identities_path)
    if any(i.severity == "ERROR" for i in id_issues):
        print(f"Error loading identities from '{settings.user_identities_path}':", file=sys.stderr)
        for err in id_issues:
            if err.severity == "ERROR":
                print(f"  {err}", file=sys.stderr)
        return 1

    audit_logs, log_issues = loader.load_user_audit_log(settings.user_audit_log_path)
    if any(i.severity == "ERROR" for i in log_issues):
        print(f"Error loading audit log from '{settings.user_audit_log_path}':", file=sys.stderr)
        for err in log_issues:
            if err.severity == "ERROR":
                print(f"  {err}", file=sys.stderr)
        return 1

    service = IdentityResolutionService.from_data(identities=identities, audit_logs=audit_logs)

    # 1. Batch mode
    if batch:
        req_path = settings.sample_deletion_requests_path if sample else settings.deletion_requests_path
        requests, req_issues = loader.load_deletion_requests(req_path)
        if any(i.severity == "ERROR" for i in req_issues):
            print(f"Error loading requests from '{req_path}':", file=sys.stderr)
            for err in req_issues:
                if err.severity == "ERROR":
                    print(f"  {err}", file=sys.stderr)
            return 1

        results: list[dict[str, Any]] = []
        status_counts = Counter()
        match_method_counts = Counter()

        for req in requests:
            res = service.resolve_request(req)
            status_counts[res.resolution_status.value] += 1
            if res.match_method:
                match_method_counts[res.match_method] += 1
            results.append(
                {
                    "case_id": req.case_id,
                    "request_email": req.email,
                    "resolution_status": res.resolution_status.value,
                    "stable_subject_reference": res.stable_subject_reference,
                    "match_method": res.match_method,
                    "candidates": res.candidates,
                    "searchable_count": len(res.searchable_identifiers),
                    "warnings_count": len(res.warnings),
                }
            )

        summary = {
            "total_requests": len(requests),
            "is_sample": sample,
            "status_counts": dict(status_counts),
            "match_methods": dict(match_method_counts),
            "cases": results,
        }

        if json_output:
            print(json.dumps(summary, indent=2, default=_json_serial))
        else:
            print("=" * 68)
            print("BATCH IDENTITY RESOLUTION SUMMARY")
            print("=" * 68)
            print(f"Mode             : {'SAMPLE' if sample else 'EVALUATION'}")
            print(f"Total Requests   : {len(requests)}")
            print("-" * 68)
            print("STATUS COUNTS:")
            for st, cnt in sorted(status_counts.items()):
                pct = (cnt / len(requests) * 100) if requests else 0.0
                print(f"  - {st:<15}: {cnt:>5} ({pct:5.1f}%)")
            print("-" * 68)
            print("MATCH METHODS (RESOLVED):")
            for m, cnt in sorted(match_method_counts.items()):
                print(f"  - {m:<32}: {cnt:>5}")
            print("=" * 68)

        if write_report:
            artifacts_dir = settings.dataset_dir.parent / "artifacts"
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            report_file = artifacts_dir / f"identity-resolution-report-{'sample' if sample else 'eval'}.md"
            with open(report_file, "w", encoding="utf-8") as rf:
                rf.write(f"# Identity Resolution Summary ({'Sample' if sample else 'Evaluation'})\n\n")
                rf.write(f"- Total Requests: {len(requests)}\n")
                for st, cnt in sorted(status_counts.items()):
                    rf.write(f"- {st}: {cnt}\n")
                rf.write("\n## Match Breakdown\n")
                for m, cnt in sorted(match_method_counts.items()):
                    rf.write(f"- {m}: {cnt}\n")
            print(f"Wrote batch report to {report_file}")

        return 0

    # 2. Case mode
    if case_id:
        req_path = settings.sample_deletion_requests_path if sample else settings.deletion_requests_path
        requests, req_issues = loader.load_deletion_requests(req_path)
        matching = [r for r in requests if r.case_id == case_id]
        if not matching:
            print(f"Error: Case ID '{case_id}' not found in {req_path.name}.", file=sys.stderr)
            return 1
        req = matching[0]
        # Allow command-line audit_at override if explicitly provided
        effective_audit_at = parse_iso_timestamp(audit_at) if audit_at else req.audit_at
        effective_req_at = parse_iso_timestamp(requested_at) if requested_at else req.requested_at
        result = service.resolve_email(
            email=req.email,
            audit_at=effective_audit_at,
            requested_at=effective_req_at,
            case_id=req.case_id,
        )

        if json_output:
            print(json.dumps(result.model_dump(), indent=2, default=_json_serial))
        else:
            print(format_identity_result_text(result, case_id=case_id))
        return 0

    # 3. Direct email mode
    assert email is not None
    assert audit_at is not None
    result = service.resolve_email(
        email=email,
        audit_at=audit_at,
        requested_at=requested_at,
    )
    if json_output:
        print(json.dumps(result.model_dump(), indent=2, default=_json_serial))
    else:
        print(format_identity_result_text(result))
    return 0
