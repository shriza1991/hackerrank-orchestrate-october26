"""Diagnostic evaluator measuring sample retrieval coverage against sample_output.csv.

Strictly read-only and diagnostic: answers from sample_output.csv are NEVER fed
into retrieval or packet construction.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

from ghost_audit.retrieval.models import CaseEvidencePacket


@dataclass
class CaseRetrievalMetric:
    """Retrieval coverage metrics for a single sample case."""

    case_id: str
    expected_resources: list[str]  # e.g. ["account_service:account_001"]
    found_resources: list[str]
    missing_resources: list[str]
    resource_coverage_pct: float

    expected_evidence_ids: list[str]  # e.g. ["evidence_54"]
    found_evidence_ids: list[str]
    missing_evidence_ids: list[str]
    evidence_coverage_pct: float

    selected_obs_count: int
    selected_act_count: int
    is_blocked: bool


@dataclass
class RetrievalEvaluationSummary:
    """Aggregated evaluation metrics across all evaluated sample cases."""

    total_cases: int
    total_expected_resources: int
    total_found_resources: int
    overall_resource_coverage_pct: float

    total_expected_evidence_ids: int
    total_found_evidence_ids: int
    overall_evidence_coverage_pct: float

    case_metrics: list[CaseRetrievalMetric] = field(default_factory=list)


def evaluate_sample_retrieval(
    packets: Sequence[CaseEvidencePacket],
    sample_output_path: Path,
) -> RetrievalEvaluationSummary:
    """Evaluate retrieval packets against target resources and evidence cited in sample_output.csv."""
    # 1. Parse sample_output.csv
    expected_by_case: dict[str, dict[str, Any]] = {}
    with open(sample_output_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cid = row["case_id"]
            steps_raw = row.get("steps_json", "[]")
            try:
                steps = json.loads(steps_raw)
            except Exception:
                steps = []

            exp_res: set[str] = set()
            exp_ev: set[str] = set()
            for s in steps:
                sys_id = s.get("system_id")
                r_id = s.get("resource_id")
                ev_id = s.get("evidence_id")

                if sys_id and r_id:
                    exp_res.add(f"{sys_id}:{r_id}")
                elif r_id:
                    exp_res.add(r_id)

                if ev_id and ev_id.strip():
                    exp_ev.add(ev_id.strip())

            expected_by_case[cid] = {
                "resources": sorted(list(exp_res)),
                "evidence_ids": sorted(list(exp_ev)),
            }

    packet_by_case = {p.case_id: p for p in packets}

    case_metrics: list[CaseRetrievalMetric] = []
    tot_exp_res = 0
    tot_found_res = 0
    tot_exp_ev = 0
    tot_found_ev = 0

    for cid, exp in sorted(expected_by_case.items()):
        pkt = packet_by_case.get(cid)
        exp_res_list = exp["resources"]
        exp_ev_list = exp["evidence_ids"]

        if not pkt:
            case_metrics.append(
                CaseRetrievalMetric(
                    case_id=cid,
                    expected_resources=exp_res_list,
                    found_resources=[],
                    missing_resources=exp_res_list,
                    resource_coverage_pct=0.0,
                    expected_evidence_ids=exp_ev_list,
                    found_evidence_ids=[],
                    missing_evidence_ids=exp_ev_list,
                    evidence_coverage_pct=0.0,
                    selected_obs_count=0,
                    selected_act_count=0,
                    is_blocked=False,
                )
            )
            tot_exp_res += len(exp_res_list)
            tot_exp_ev += len(exp_ev_list)
            continue

        # Grounded resources in packet
        packet_grounded = set(pkt.grounded_resources)
        # Also include resource_id from selected observations and activities
        for so in pkt.selected_observations:
            if so.observation.system_id and so.observation.resource_id:
                packet_grounded.add(f"{so.observation.system_id}:{so.observation.resource_id}")
            if so.observation.resource_id:
                packet_grounded.add(so.observation.resource_id)
        for sa in pkt.selected_activities:
            packet_grounded.add(f"{sa.target_system}:{sa.resource_id}")
            packet_grounded.add(sa.resource_id)

        found_res: list[str] = []
        missing_res: list[str] = []
        for r in exp_res_list:
            # Check full match or resource_id match
            r_id_only = r.split(":")[-1] if ":" in r else r
            if r in packet_grounded or r_id_only in packet_grounded or any(g.endswith(f":{r_id_only}") for g in packet_grounded):
                found_res.append(r)
            else:
                missing_res.append(r)

        res_pct = (len(found_res) / len(exp_res_list) * 100.0) if exp_res_list else 100.0

        # Found evidence IDs
        packet_evidence_ids = {so.observation.evidence_id for so in pkt.selected_observations}
        # Also check scoped inventories
        for si in pkt.scoped_inventories:
            packet_evidence_ids.add(si.source_id)

        found_ev: list[str] = []
        missing_ev: list[str] = []
        for ev in exp_ev_list:
            if ev in packet_evidence_ids:
                found_ev.append(ev)
            else:
                missing_ev.append(ev)

        ev_pct = (len(found_ev) / len(exp_ev_list) * 100.0) if exp_ev_list else 100.0

        case_metrics.append(
            CaseRetrievalMetric(
                case_id=cid,
                expected_resources=exp_res_list,
                found_resources=found_res,
                missing_resources=missing_res,
                resource_coverage_pct=res_pct,
                expected_evidence_ids=exp_ev_list,
                found_evidence_ids=found_ev,
                missing_evidence_ids=missing_ev,
                evidence_coverage_pct=ev_pct,
                selected_obs_count=len(pkt.selected_observations),
                selected_act_count=len(pkt.selected_activities),
                is_blocked=pkt.is_blocked,
            )
        )

        tot_exp_res += len(exp_res_list)
        tot_found_res += len(found_res)
        tot_exp_ev += len(exp_ev_list)
        tot_found_ev += len(found_ev)

    overall_res_pct = (tot_found_res / tot_exp_res * 100.0) if tot_exp_res else 100.0
    overall_ev_pct = (tot_found_ev / tot_exp_ev * 100.0) if tot_exp_ev else 100.0

    return RetrievalEvaluationSummary(
        total_cases=len(case_metrics),
        total_expected_resources=tot_exp_res,
        total_found_resources=tot_found_res,
        overall_resource_coverage_pct=overall_res_pct,
        total_expected_evidence_ids=tot_exp_ev,
        total_found_evidence_ids=tot_found_ev,
        overall_evidence_coverage_pct=overall_ev_pct,
        case_metrics=case_metrics,
    )


def format_evaluation_summary(summary: RetrievalEvaluationSummary) -> str:
    """Format evaluation summary into text table."""
    lines = [
        "=" * 78,
        "PUBLIC SAMPLE RETRIEVAL EVALUATION REPORT",
        "=" * 78,
        f"Total Cases Evaluated        : {summary.total_cases}",
        f"Resource Targets Expected    : {summary.total_expected_resources}",
        f"Resource Targets Grounded    : {summary.total_found_resources} ({summary.overall_resource_coverage_pct:.1f}%)",
        f"Evidence IDs Cited Expected  : {summary.total_expected_evidence_ids}",
        f"Evidence IDs Retrieved       : {summary.total_found_evidence_ids} ({summary.overall_evidence_coverage_pct:.1f}%)",
        "-" * 78,
        f"{'Case ID':<9} | {'Res Found':<10} | {'Res %':<6} | {'Ev Found':<9} | {'Ev %':<6} | {'Missing Targets'}",
        "-" * 78,
    ]
    for m in summary.case_metrics:
        res_str = f"{len(m.found_resources)}/{len(m.expected_resources)}"
        ev_str = f"{len(m.found_evidence_ids)}/{len(m.expected_evidence_ids)}"
        miss_str = ", ".join(m.missing_resources[:2]) if m.missing_resources else "(none)"
        if len(m.missing_resources) > 2:
            miss_str += f" (+{len(m.missing_resources)-2} more)"
        lines.append(f"{m.case_id:<9} | {res_str:<10} | {m.resource_coverage_pct:>5.1f}% | {ev_str:<9} | {m.evidence_coverage_pct:>5.1f}% | {miss_str}")

    lines.append("=" * 78)
    return "\n".join(lines)
