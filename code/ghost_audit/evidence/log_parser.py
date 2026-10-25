"""Log and plain-text evidence parser supporting JSON lines, key-value, traces, syslog, and handovers."""

import json
import re
from datetime import datetime
from typing import Any, Optional

from ghost_audit.evidence.common import (
    compute_content_digest,
    extract_subject_references,
    make_observation_id,
)
from ghost_audit.evidence.models import (
    FileIngestionResult,
    IngestionStatus,
    ObservationType,
)
from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.timestamps import parse_iso_timestamp


PARSER_NAME = "LogEvidenceParser"
PARSER_VERSION = "1.0.0"

# Regex for key="value with escapes" or key=unquoted
KV_PATTERN = re.compile(r'([a-zA-Z0-9_\-]+)=(?:"((?:\\.|[^"\\])*)"|([^\s]+))')

# Structured JSON log line: <ISO_TS> {JSON}
JSON_LOG_RE = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s+(?P<json>\{.*\})$')

# Plain-text shift handover line: - <ISO_TS> | <system> | <resource_id> | <type> | <status> | <subject>
HANDOVER_RE = re.compile(
    r'^-\s+(?P<ts>\d{4}-\d{2}-\d{2}T[^\s|]+)\s*\|\s*(?P<system>[^|]+)\|\s*(?P<res>[^|]+)\|\s*(?P<type>[^|]+)\|\s*(?P<status>[^|]+)\|\s*(?P<subject>.*)$'
)

# Pipe-delimited stream: <ISO_TS> | <LEVEL> | <system> | <trace> | <event> | <kv>
PIPE_STREAM_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s|]+)\s*\|\s*(?P<level>[A-Z]+)\s*\|\s*(?P<system>[^|]+)\|\s*(?P<trace>[^|]+)\|\s*(?P<event>[^|]+)\|\s*(?P<kv>.*)$'
)

# Bracketed trace log: <ISO_TS> [<LEVEL>] [<system>] [<trace>] <event>:? <kv>
BRACKETED_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s+\[(?P<level>[A-Z]+)\]\s+\[(?P<system>[^\]]+)\]\s+\[(?P<trace>[^\]]+)\]\s+(?P<event>[a-zA-Z0-9_\-]+):?\s*(?P<kv>.*)$'
)

# Cloud runtime export: <ISO_TS> requestId=<req> level=<level> function=<func> message="<msg>"
CLOUD_RUNTIME_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s+requestId=(?P<req>[^\s]+)\s+level=(?P<level>[A-Z]+)\s+function=(?P<func>[^\s]+)\s+message="(?P<msg>.*)"$'
)

# Syslog RFC-5424: <ISO_TS> <pri>ver host app proc - - <rest>
SYSLOG_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s+<(?P<pri>\d+)>(?P<ver>\d+)\s+(?P<host>[^\s]+)\s+(?P<app>[^\s]+)\s+(?P<proc>[^\s]+)\s+-\s+-\s+(?P<rest>.*)$'
)

# Standard KV log: <ISO_TS> [LEVEL] key=value ...
STANDARD_KV_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s+(?:(?P<level>[A-Z]+)\s+)?(?P<kv>[a-zA-Z0-9_\-]+=.+)$'
)


def parse_key_value_pairs(text: str) -> dict[str, Any]:
    """Parse key=value pairs handling quoted strings with escapes and types."""
    res: dict[str, Any] = {}
    for match in KV_PATTERN.finditer(text):
        k = match.group(1)
        if match.group(2) is not None:
            v_str = match.group(2).replace(r'\"', '"').replace(r"\'", "'").replace(r'\\', '\\')
            res[k] = v_str
        else:
            raw_v = match.group(3)
            # Preserve booleans, null, numbers where explicit
            if raw_v.lower() == "true":
                res[k] = True
            elif raw_v.lower() == "false":
                res[k] = False
            elif raw_v.lower() == "null" or raw_v.lower() == "none":
                res[k] = None
            elif raw_v.isdigit():
                res[k] = int(raw_v)
            else:
                res[k] = raw_v
    return res


def determine_log_obs_type(facts: dict[str, Any], event_name: Optional[str]) -> str:
    """Classify the observation type of a log entry based on its semantic attributes."""
    if "result" in facts or "rows" in facts or "total_hits" in facts or "http_status" in facts or "latency_ms" in facts:
        return ObservationType.LOOKUP_RESULT.value
    if "enabled" in facts or "restore_allowed" in facts or "last_delivery_status" in facts or "marker_found" in facts:
        return ObservationType.PROCESS_CONFIG.value
    if "record_type" in facts or "message_excerpt" in facts:
        return ObservationType.STORED_RECORD.value
    
    # Check event names
    ev = (event_name or facts.get("event") or "").lower()
    if "lookup_completed" in ev or "query_completed" in ev or "read_completed" in ev:
        return ObservationType.LOOKUP_RESULT.value
    if "export_started" in ev or "batch_started" in ev or "checkpoint_saved" in ev or "delivery_abandoned" in ev or "pool_sample" in ev or "lease_extended" in ev or "cache_refresh" in ev:
        return ObservationType.OPERATIONAL_CLAIM.value
    if "lookup_started" in ev or "query_started" in ev or "read_started" in ev or "scan_started" in ev:
        return ObservationType.OPERATIONAL_CLAIM.value

    return ObservationType.OPERATIONAL_CLAIM.value


class LogEvidenceParser:
    """Parser for unstructured and structured log streams and plain text handovers."""

    def __init__(self):
        self.parser_name = PARSER_NAME
        self.parser_version = PARSER_VERSION

    def parse(
        self,
        file_id: str,
        file_path: str,
        origin: str,
        manifest_captured_at: datetime,
        content: str,
    ) -> FileIngestionResult:
        """Parse log/text lines into structured EvidenceObservation records."""
        content_digest = compute_content_digest(content)
        lines = content.splitlines()

        parsed_entries: list[dict[str, Any]] = []
        unparsed_fragments: list[dict[str, Any]] = []
        warnings: list[str] = []

        # Pass 1: Parse individual lines
        for line_no, raw_line in enumerate(lines, start=1):
            s = raw_line.strip()
            if not s:
                continue

            # Handover document headers
            if s.startswith("CUSTOMER PLATFORM") or s.startswith("Snapshot:") or s.startswith("Account and downstream"):
                continue

            # 1. Plain-text handover row
            m_ho = HANDOVER_RE.match(s)
            if m_ho:
                ts_str = m_ho.group("ts")
                sys_id = m_ho.group("system").strip()
                res_id = m_ho.group("res").strip()
                rec_type = m_ho.group("type").strip()
                status = m_ho.group("status").strip()
                subject_val = m_ho.group("subject").strip()

                facts = {
                    "system": sys_id,
                    "resource_id": res_id,
                    "record_type": rec_type,
                    "status": status,
                    "subject_reference": subject_val,
                    "raw_line": s,
                }
                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": None,
                    "event": "handover_check",
                    "facts": facts,
                    "obs_type": ObservationType.STORED_RECORD.value,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 2. Structured JSON log line
            m_json = JSON_LOG_RE.match(s)
            if m_json:
                ts_str = m_json.group("ts")
                json_str = m_json.group("json")
                try:
                    rec_dict = json.loads(json_str)
                except Exception as e:
                    unparsed_fragments.append({"line_no": line_no, "raw_line": s, "error": str(e)})
                    continue

                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                sys_id = rec_dict.get("service") or rec_dict.get("logger") or origin
                res_id = rec_dict.get("resource_id")
                trace_id = rec_dict.get("trace_id")
                event_name = rec_dict.get("event")
                facts = dict(rec_dict)
                facts["raw_line"] = s

                obs_type = determine_log_obs_type(facts, event_name)

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": trace_id,
                    "event": event_name,
                    "facts": facts,
                    "obs_type": obs_type,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 3. Pipe-delimited stream
            m_pipe = PIPE_STREAM_RE.match(s)
            if m_pipe:
                ts_str = m_pipe.group("ts")
                sys_id = m_pipe.group("system").strip()
                trace_id = m_pipe.group("trace").strip()
                event_name = m_pipe.group("event").strip()
                kv_text = m_pipe.group("kv")
                facts = parse_key_value_pairs(kv_text)
                facts["level"] = m_pipe.group("level").strip()
                facts["event"] = event_name
                facts["raw_line"] = s

                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                res_id = facts.get("resource_id")
                obs_type = determine_log_obs_type(facts, event_name)

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": trace_id if trace_id != "-" else None,
                    "event": event_name,
                    "facts": facts,
                    "obs_type": obs_type,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 4. Bracketed trace log
            m_brack = BRACKETED_RE.match(s)
            if m_brack:
                ts_str = m_brack.group("ts")
                sys_id = m_brack.group("system").strip()
                trace_id = m_brack.group("trace").strip()
                event_name = m_brack.group("event").strip()
                kv_text = m_brack.group("kv")
                facts = parse_key_value_pairs(kv_text)
                facts["level"] = m_brack.group("level").strip()
                facts["event"] = event_name
                facts["raw_line"] = s

                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                res_id = facts.get("resource_id")
                obs_type = determine_log_obs_type(facts, event_name)

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": trace_id if trace_id != "-" else None,
                    "event": event_name,
                    "facts": facts,
                    "obs_type": obs_type,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 5. Cloud runtime export log
            m_cloud = CLOUD_RUNTIME_RE.match(s)
            if m_cloud:
                ts_str = m_cloud.group("ts")
                trace_id = m_cloud.group("req").strip()
                sys_id = m_cloud.group("func").strip()
                msg_text = m_cloud.group("msg")

                # Cloud runtime logs escape inner quotes with \"
                clean_msg_text = msg_text.replace(r'\"', '"')
                inner_facts = parse_key_value_pairs(clean_msg_text)
                facts = {
                    "requestId": trace_id,
                    "level": m_cloud.group("level").strip(),
                    "function": sys_id,
                    **inner_facts,
                    "raw_line": s,
                }

                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                event_name = facts.get("event")
                res_id = facts.get("resource_id")
                obs_type = determine_log_obs_type(facts, event_name)

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": trace_id if trace_id != "-" else None,
                    "event": event_name,
                    "facts": facts,
                    "obs_type": obs_type,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 6. Syslog RFC-5424
            m_syslog = SYSLOG_RE.match(s)
            if m_syslog:
                ts_str = m_syslog.group("ts")
                sys_id = m_syslog.group("app").strip()
                trace_id = m_syslog.group("proc").strip()
                rest_kv = m_syslog.group("rest")
                facts = parse_key_value_pairs(rest_kv)
                facts["host"] = m_syslog.group("host").strip()
                facts["raw_line"] = s

                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                event_name = facts.get("event")
                res_id = facts.get("resource_id")
                obs_type = determine_log_obs_type(facts, event_name)

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": trace_id if trace_id != "-" else None,
                    "event": event_name,
                    "facts": facts,
                    "obs_type": obs_type,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 7. Standard KV log
            m_kv = STANDARD_KV_RE.match(s)
            if m_kv:
                ts_str = m_kv.group("ts")
                kv_text = m_kv.group("kv")
                facts = parse_key_value_pairs(kv_text)
                if m_kv.group("level"):
                    facts["level"] = m_kv.group("level").strip()
                facts["raw_line"] = s

                obs_time = manifest_captured_at
                try:
                    obs_time = parse_iso_timestamp(ts_str)
                except Exception:
                    pass

                sys_id = facts.get("service") or facts.get("system") or origin
                res_id = facts.get("resource_id")
                trace_id = facts.get("trace_id")
                event_name = facts.get("event")
                obs_type = determine_log_obs_type(facts, event_name)

                parsed_entries.append({
                    "line_no": line_no,
                    "timestamp": obs_time,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "trace_id": trace_id if trace_id != "-" else None,
                    "event": event_name,
                    "facts": facts,
                    "obs_type": obs_type,
                    "subject_refs": extract_subject_references(facts),
                    "raw_text": s,
                })
                continue

            # 8. Unrecognized line
            unparsed_fragments.append({"line_no": line_no, "raw_line": s})

        # Pass 2: Trace correlation for split traces
        # Group entries by trace key within file
        trace_map: dict[tuple[str, str], list[int]] = {}
        for idx, entry in enumerate(parsed_entries):
            tr_id = entry.get("trace_id")
            if tr_id:
                # Scope trace ID by (system_id, trace_id)
                tr_key = (entry["system_id"], tr_id)
                trace_map.setdefault(tr_key, []).append(idx)

        for (svc, tr_id), entry_indices in trace_map.items():
            if len(entry_indices) > 1:
                # Find all subjects and resources across this trace
                all_subjects: set[str] = set()
                all_resources: set[str] = set()
                start_lines: list[int] = []
                end_lines: list[int] = []

                for idx in entry_indices:
                    ent = parsed_entries[idx]
                    all_subjects.update(ent["subject_refs"])
                    if ent["resource_id"]:
                        all_resources.add(ent["resource_id"])
                    ev = (ent.get("event") or "").lower()
                    if "start" in ev:
                        start_lines.append(ent["line_no"])
                    elif "completed" in ev or "finish" in ev or "result" in ev:
                        end_lines.append(ent["line_no"])

                # Detect potential trace collisions (multiple disparate subjects in same trace ID)
                if len(all_subjects) > 2:
                    warnings.append(
                        f"Potential trace ID collision for {tr_id} in service {svc}: multiple subjects found {sorted(all_subjects)}"
                    )

                # Correlate across split trace entries
                for idx in entry_indices:
                    ent = parsed_entries[idx]
                    # Link subject references from other entries in the trace
                    for sub in all_subjects:
                        if sub not in ent["subject_refs"]:
                            ent["subject_refs"].append(sub)
                    # Link resource ID if missing on start event
                    if not ent["resource_id"] and len(all_resources) == 1:
                        ent["facts"]["correlated_resource_id"] = next(iter(all_resources))
                    if start_lines:
                        ent["facts"]["correlated_trace_start_line"] = start_lines[0]
                    if end_lines:
                        ent["facts"]["correlated_trace_end_line"] = end_lines[-1]

        # Pass 3: Construct EvidenceObservation objects
        observations: list[EvidenceObservation] = []
        obs_idx = 0

        for ent in parsed_entries:
            obs_idx += 1
            locator = f"line:{ent['line_no']}"
            observations.append(
                EvidenceObservation(
                    evidence_id=file_id,
                    source_locator=locator,
                    capture_time=manifest_captured_at,
                    observation_time=ent["timestamp"],
                    system_id=ent["system_id"],
                    resource_id=ent["resource_id"],
                    extracted_facts=ent["facts"],
                    extraction_method=self.parser_name,
                    uncertainty_or_warnings=[],
                    internal_id=make_observation_id(file_id, obs_idx),
                    file_path=file_path,
                    observation_type=ent["obs_type"],
                    scope_context={"line_no": ent["line_no"], "trace_id": ent["trace_id"]},
                    subject_references=sorted(set(ent["subject_refs"])),
                    content_digest=content_digest,
                )
            )

        # Emit RAW_FRAGMENT observations for any unparsed fragments
        for frag in unparsed_fragments:
            obs_idx += 1
            line_no = frag["line_no"]
            locator = f"line:{line_no}"
            warnings.append(f"Unrecognized log fragment at line {line_no}")
            observations.append(
                EvidenceObservation(
                    evidence_id=file_id,
                    source_locator=locator,
                    capture_time=manifest_captured_at,
                    observation_time=manifest_captured_at,
                    system_id=origin,
                    resource_id=None,
                    extracted_facts={"raw_text": frag["raw_line"], "unparsed": True},
                    extraction_method=self.parser_name,
                    uncertainty_or_warnings=[f"Unrecognized log format at line {line_no}"],
                    internal_id=make_observation_id(file_id, obs_idx),
                    file_path=file_path,
                    observation_type=ObservationType.RAW_FRAGMENT.value,
                    scope_context={"line_no": line_no},
                    subject_references=[],
                    content_digest=content_digest,
                )
            )

        status = IngestionStatus.PARSED if not unparsed_fragments and not warnings else IngestionStatus.PARTIAL

        return FileIngestionResult(
            file_id=file_id,
            file_path=file_path,
            origin=origin,
            format="log" if file_path.endswith(".log") else "txt",
            status=status,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            observation_count=len(observations),
            observations=observations,
            warnings=warnings,
            errors=[],
            unparsed_fragments=unparsed_fragments,
            content_digest=content_digest,
        )
