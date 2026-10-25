"""Source-aware timestamp interpretation distinguishing observation, capture, and business times."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.models.input_models import SystemActivityEvent
from ghost_audit.timestamps import parse_iso_timestamp


@dataclass(frozen=True)
class InterpretedTimestamps:
    """Interpreted timestamp roles with grounded justification."""

    state_observation_time: datetime
    capture_time: datetime
    business_mutation_time: Optional[datetime] = None
    retention_expiry: Optional[datetime] = None
    time_role_basis: str = ""
    is_eligible: bool = True


class SourceAwareTimestampInterpreter:
    """Interprets timestamps based on evidence format, source origin, and fact semantics."""

    @staticmethod
    def interpret_observation(
        obs: EvidenceObservation,
        audit_at: datetime,
    ) -> InterpretedTimestamps:
        """Interpret timestamps for an EvidenceObservation with source role awareness."""
        capture_time = obs.capture_time
        facts = obs.extracted_facts or {}
        obs_type = (obs.observation_type or "").upper()
        file_path = (obs.file_path or "").lower()

        business_time: Optional[datetime] = None
        retention_time: Optional[datetime] = None

        # Check for retention expiry metadata
        if "retention_until" in facts:
            try:
                retention_time = parse_iso_timestamp(facts["retention_until"])
            except Exception:
                pass
        elif "retention" in facts and isinstance(facts["retention"], dict):
            ret_dict = facts["retention"]
            ret_str = ret_dict.get("retention_until_iso") or ret_dict.get("retention_until")
            if ret_str:
                try:
                    retention_time = parse_iso_timestamp(ret_str)
                except Exception:
                    pass

        # Check for business mutation timestamps inside facts
        for candidate_key in ["updated_at", "created_at", "order_date", "mutation_time", "registered_at", "timestamp"]:
            if candidate_key in facts and facts[candidate_key]:
                try:
                    candidate_dt = parse_iso_timestamp(facts[candidate_key])
                    # Ensure it is not identical to capture time unless that's all there is
                    business_time = candidate_dt
                    break
                except Exception:
                    pass

        # 1. SQL Snapshot: The point-in-time snapshot capture time observes the state
        if file_path.endswith(".sql") or "SQL" in obs.extraction_method.upper() or "table:" in (obs.source_locator or ""):
            state_time = capture_time
            basis = "SQL point-in-time snapshot capture time establishes state observation; row timestamps represent business mutation."

        # 2. Log Entry: The log event timestamp is when the event was observed; export is archive time
        elif file_path.endswith(".log") or "LOG" in obs_type or obs.extraction_method == "LOG_PATTERN":
            if obs.observation_time:
                state_time = obs.observation_time
                basis = "Log event timestamp establishes state observation time; file capture time is log archive/export time."
            else:
                state_time = capture_time
                basis = "Log file capture time establishes state observation time (no separate event time)."

        # 3. Screenshot / UI: Capture time is visual observation time; on-screen text is business info
        elif file_path.endswith(".png") or "OCR" in obs.extraction_method.upper() or "IMAGE" in obs_type:
            state_time = capture_time
            basis = "Screenshot capture time establishes visual console observation time; on-screen dates are business metadata."

        # 4. Document / PDF: Capture time is stored document observation time; order date is business creation
        elif file_path.endswith(".pdf") or "PDF" in obs.extraction_method.upper() or "DOCUMENT" in obs_type:
            state_time = capture_time
            basis = "Document capture time establishes stored artifact observation time; document dates represent business events."

        # 5. JSON Snapshot / Export
        elif file_path.endswith(".json") or "JSON" in obs_type:
            if obs.observation_time:
                state_time = obs.observation_time
                basis = "JSON snapshot observation timestamp establishes state observation time."
            else:
                state_time = capture_time
                basis = "JSON file capture time establishes state observation time."

        # Default fallback
        else:
            state_time = obs.observation_time or capture_time
            basis = "Observation timestamp establishes state observation time."

        is_eligible = (state_time <= audit_at) and (capture_time <= audit_at)

        return InterpretedTimestamps(
            state_observation_time=state_time,
            capture_time=capture_time,
            business_mutation_time=business_time,
            retention_expiry=retention_time,
            time_role_basis=basis,
            is_eligible=is_eligible,
        )

    @staticmethod
    def interpret_activity(
        act: SystemActivityEvent,
        audit_at: datetime,
    ) -> InterpretedTimestamps:
        """Interpret timestamps for a SystemActivityEvent."""
        event_time = act.event_time
        is_eligible = (event_time <= audit_at)
        return InterpretedTimestamps(
            state_observation_time=event_time,
            capture_time=event_time,
            business_mutation_time=None,
            retention_expiry=None,
            time_role_basis="System activity event timestamp establishes operation occurrence time.",
            is_eligible=is_eligible,
        )
