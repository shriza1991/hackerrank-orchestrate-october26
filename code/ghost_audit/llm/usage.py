"""Per-attempt accounting, Decimal cost aggregation, and report rendering."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path

from ghost_audit.llm.types import ProviderUsage, UsageRecord

MILLION = Decimal("1000000")


def estimate_cost(usage: ProviderUsage | None, input_price: Decimal | None,
                  output_price: Decimal | None) -> Decimal | None:
    if usage is None or usage.input_tokens is None or usage.output_tokens is None:
        return None
    if input_price is None or output_price is None:
        return None
    return (Decimal(usage.input_tokens) * input_price + Decimal(usage.output_tokens) * output_price) / MILLION


class UsageTracker:
    def __init__(self) -> None:
        self.records: list[UsageRecord] = []

    def add(self, record: UsageRecord) -> None:
        self.records.append(record)

    def machine_records(self) -> list[dict]:
        values = []
        for record in self.records:
            item = asdict(record)
            item["estimated_cost"] = str(record.estimated_cost) if record.estimated_cost is not None else None
            values.append(item)
        return values

    @staticmethod
    def _json_safe(value):
        """Losslessly encode Decimal values while preserving unknowns as null."""

        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, dict):
            return {key: UsageTracker._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [UsageTracker._json_safe(item) for item in value]
        return value

    def report_payload(self, *, run_provenance: dict | None = None) -> dict:
        """Return a persistent report containing aggregates and every attempt."""

        return {
            "schema_version": 1,
            "run_provenance": self._json_safe(run_provenance or {}),
            "summary": self._json_safe(self.summary()),
            "attempts": self.machine_records(),
        }

    def write_json(self, path: Path, *, run_provenance: dict | None = None) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.report_payload(run_provenance=run_provenance), indent=2),
            encoding="utf-8",
            newline="\n",
        )

    def summary(self) -> dict:
        groups: dict[tuple[str, str], list[UsageRecord]] = defaultdict(list)
        for record in self.records:
            groups[(record.provider, record.provider_model or record.requested_model)].append(record)

        def aggregate(records: list[UsageRecord]) -> dict:
            new = [r for r in records if r.new_api_request]
            known_input = sum(r.input_tokens for r in new if r.input_tokens is not None)
            known_output = sum(r.output_tokens for r in new if r.output_tokens is not None)
            unknown = sum(1 for r in new if r.input_tokens is None or r.output_tokens is None)
            costs = [r.estimated_cost for r in new]
            cost_available = bool(new) and unknown == 0 and all(value is not None for value in costs)
            cost = sum((value for value in costs if value is not None), Decimal("0")) if cost_available else None
            logical = len({r.logical_request_id for r in records})
            logical_tokens = known_input + known_output + sum(r.reused_input_tokens + r.reused_output_tokens for r in records)
            return {
                "logical_requests": logical,
                "new_api_attempts": len(new),
                "successful_calls": sum(1 for r in new if r.outcome == "SUCCESS"),
                "failed_attempts": sum(1 for r in new if r.outcome != "SUCCESS"),
                "cache_hits": sum(1 for r in records if not r.new_api_request and r.outcome == "CACHE_HIT"),
                "known_input_tokens": known_input,
                "known_output_tokens": known_output,
                "reused_input_tokens": sum(r.reused_input_tokens for r in records),
                "reused_output_tokens": sum(r.reused_output_tokens for r in records),
                "unknown_usage_attempts": unknown,
                "average_logical_tokens": (Decimal(logical_tokens) / logical) if logical else Decimal("0"),
                "estimated_cost": cost,
                "estimated_cost_per_request": (cost / logical) if cost is not None and logical else None,
            }

        overall = aggregate(self.records)
        per_model = {f"{provider}/{model}": aggregate(records) for (provider, model), records in sorted(groups.items())}
        return {"overall": overall, "per_provider_model": per_model}

    def render_markdown(self, *, development: bool = True) -> str:
        summary = self.summary()
        overall = summary["overall"]
        cost = overall["estimated_cost"]
        lines = ["# Development Model Usage Report", ""]
        if development:
            lines.extend(["> Development smoke-test accounting only. This is not the final full-dataset usage report.", ""])
        lines.extend([
            "## Overall", "",
            f"- Logical requests: {overall['logical_requests']}",
            f"- New API attempts: {overall['new_api_attempts']}",
            f"- Successful calls: {overall['successful_calls']}",
            f"- Failed attempts: {overall['failed_attempts']}",
            f"- Cache hits: {overall['cache_hits']}",
            f"- Known input/output tokens: {overall['known_input_tokens']} / {overall['known_output_tokens']}",
            f"- Reused cached input/output tokens: {overall['reused_input_tokens']} / {overall['reused_output_tokens']}",
            f"- Unknown-usage attempts: {overall['unknown_usage_attempts']}",
            f"- Estimated cost: {cost if cost is not None else 'unavailable'}", "",
            "## Per provider/model", "", "| Provider/model | API attempts | Input tokens | Output tokens | Cache hits | Estimated cost |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ])
        for name, values in summary["per_provider_model"].items():
            model_cost = values["estimated_cost"]
            lines.append(
                f"| {name} | {values['new_api_attempts']} | {values['known_input_tokens']} | "
                f"{values['known_output_tokens']} | {values['cache_hits']} | "
                f"{model_cost if model_cost is not None else 'unavailable'} |"
            )
        lines.extend(["",
            "Provider token-detail fields are reported as subsets of provider totals and are not added again. Prices, when configured, are user-supplied per-million-token estimates.", "",
            "## Machine-readable records", "", "```json",
            json.dumps(self.machine_records(), indent=2), "```", "",
        ])
        return "\n".join(lines)

    def write_markdown(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render_markdown(), encoding="utf-8", newline="\n")
