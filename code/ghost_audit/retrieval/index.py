"""In-memory indexing for evidence observations, system activity, and catalog links."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Sequence

from ghost_audit.identity.normalization import normalize_email, normalize_phone
from ghost_audit.models.input_models import SystemActivityEvent
from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.timestamps import parse_iso_timestamp


@dataclass(frozen=True)
class CatalogLinkEntry:
    """Authoritative mapping parsed from LINK_RESOURCE_IDENTITY activity events."""

    activity_id: str
    event_time: datetime
    canonical_resource_id: str
    target_system: str
    external_alias: Optional[str]
    email: Optional[str]
    user_id: Optional[str]
    details: str


_EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_USER_ID_REGEX = re.compile(r"\b(user_\w+)\b")
_ALIAS_REGEX = re.compile(r"\(([^)]+)\)")


def parse_catalog_link(event: SystemActivityEvent) -> Optional[CatalogLinkEntry]:
    """Parse a LINK_RESOURCE_IDENTITY activity event into a structured CatalogLinkEntry."""
    if event.event_type != "LINK_RESOURCE_IDENTITY":
        return None

    email_match = _EMAIL_REGEX.search(event.details)
    user_match = _USER_ID_REGEX.search(event.details)
    alias_match = _ALIAS_REGEX.search(event.details)

    email = normalize_email(email_match.group(0)) if email_match else None
    user_id = user_match.group(1) if user_match else None
    alias = alias_match.group(1).strip() if alias_match else None

    return CatalogLinkEntry(
        activity_id=event.activity_id,
        event_time=event.event_time,
        canonical_resource_id=event.resource_id,
        target_system=event.target_system,
        external_alias=alias,
        email=email,
        user_id=user_id,
        details=event.details,
    )

def _obs_key(obs: EvidenceObservation) -> tuple[str, Optional[str], Optional[str], datetime]:
    return (obs.evidence_id, obs.source_locator, obs.internal_id, obs.capture_time)


def _dedup_obs(obs_list: Sequence[EvidenceObservation]) -> list[EvidenceObservation]:
    seen = set()
    deduped = []
    for o in obs_list:
        k = _obs_key(o)
        if k not in seen:
            seen.add(k)
            deduped.append(o)
    return deduped


def _dedup_acts(act_list: Sequence[SystemActivityEvent]) -> list[SystemActivityEvent]:
    seen = set()
    deduped = []
    for a in act_list:
        if a.activity_id not in seen:
            seen.add(a.activity_id)
            deduped.append(a)
    return deduped


def _extract_identifiers_from_dict(
    d: dict[str, Any],
    idents: set[str],
    resources: set[tuple[Optional[str], str]],
    aliases: set[str],
) -> None:
    """Recursively extract candidate identifiers, resource keys, and aliases from dictionaries and embedded JSON."""
    for k, v in d.items():
        if isinstance(v, dict):
            _extract_identifiers_from_dict(v, idents, resources, aliases)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    _extract_identifiers_from_dict(item, idents, resources, aliases)
                elif isinstance(item, str) and k in {"linked_resources", "resources"}:
                    aliases.add(item.strip())
        elif isinstance(v, str):
            v_str = v.strip()
            if not v_str or v_str.lower() in {"null", "none"}:
                continue
            if (v_str.startswith("{") and v_str.endswith("}")) or (v_str.startswith("[") and v_str.endswith("]")):
                try:
                    parsed = json.loads(v_str)
                    if isinstance(parsed, dict):
                        _extract_identifiers_from_dict(parsed, idents, resources, aliases)
                        continue
                    elif isinstance(parsed, list):
                        for elem in parsed:
                            if isinstance(elem, dict):
                                _extract_identifiers_from_dict(elem, idents, resources, aliases)
                        continue
                except Exception:
                    pass

            if k in {
                "user_id", "email", "phone", "email_hash", "subject_id",
                "customer_id", "account_id", "customer_reference",
                "subject_reference", "lookup_key", "customer_email", "requester_email"
            }:
                idents.add(v_str)
            elif k in {"resource_id", "target_resource"}:
                sys_id = d.get("origin_system") or d.get("system_id") or d.get("service")
                resources.add((sys_id, v_str))
            elif k in {"file_name", "attachment_file", "export_job_id", "external_reference", "display_ref", "trace_id", "correlation_key", "requestId", "archive_key"}:
                aliases.add(v_str)


class CorpusIndex:
    """Pre-built in-memory index over evidence observations and system activity.

    Built once per process to ensure deterministic O(1) multi-criteria retrieval
    without repeated corpus rescanning.
    """

    def __init__(
        self,
        observations: Sequence[EvidenceObservation] = (),
        activity_events: Sequence[SystemActivityEvent] = (),
    ) -> None:
        self.observations: list[EvidenceObservation] = list(observations)
        self.activity_events: list[SystemActivityEvent] = list(activity_events)

        # Index observations by normalized identifier string
        self.obs_by_identifier: dict[str, list[EvidenceObservation]] = {}
        # Index observations by (system_id, resource_id)
        self.obs_by_system_resource: dict[tuple[str, str], list[EvidenceObservation]] = {}
        # Index observations by resource_id alone
        self.obs_by_resource: dict[str, list[EvidenceObservation]] = {}
        # Index observations by external reference / alias / filename
        self.obs_by_alias: dict[str, list[EvidenceObservation]] = {}
        # Index scoped inventories by system_id
        self.inventories_by_system: dict[str, list[EvidenceObservation]] = {}

        # Index activity events
        self.activity_by_resource: dict[str, list[SystemActivityEvent]] = {}
        self.activity_by_system_resource: dict[tuple[str, str], list[SystemActivityEvent]] = {}

        # Catalog links from LINK_RESOURCE_IDENTITY
        self.catalog_links: list[CatalogLinkEntry] = []
        self.catalog_by_user_id: dict[str, list[CatalogLinkEntry]] = {}
        self.catalog_by_email: dict[str, list[CatalogLinkEntry]] = {}
        self.catalog_by_resource_id: dict[str, list[CatalogLinkEntry]] = {}
        self.catalog_by_alias: dict[str, list[CatalogLinkEntry]] = {}

        self._build_indexes()

    def _build_indexes(self) -> None:
        # 1. Index activity events and catalog links
        for act in self.activity_events:
            r_id = act.resource_id.strip() if act.resource_id else None
            if r_id:
                self.activity_by_resource.setdefault(r_id, []).append(act)
                if act.target_system:
                    self.activity_by_system_resource.setdefault(
                        (act.target_system.strip(), r_id), []
                    ).append(act)

            if act.event_type == "LINK_RESOURCE_IDENTITY":
                entry = parse_catalog_link(act)
                if entry:
                    self.catalog_links.append(entry)
                    if entry.user_id:
                        self.catalog_by_user_id.setdefault(entry.user_id, []).append(entry)
                    if entry.email:
                        self.catalog_by_email.setdefault(entry.email, []).append(entry)
                    if entry.canonical_resource_id:
                        self.catalog_by_resource_id.setdefault(
                            entry.canonical_resource_id, []
                        ).append(entry)
                    if entry.external_alias:
                        self.catalog_by_alias.setdefault(
                            entry.external_alias, []
                        ).append(entry)

        # 2. Index observations
        for obs in self.observations:
            # Check for scoped inventories
            if (
                obs.observation_type in {"INVENTORY_SCOPE", "TABLE_INVENTORY"}
                or "inventory" in obs.extracted_facts
                or "table_rows" in obs.extracted_facts
                or (obs.source_locator and "failover_replica" in obs.source_locator)
            ):
                if obs.system_id:
                    self.inventories_by_system.setdefault(obs.system_id, []).append(obs)

            # Direct subject references
            for ref in obs.subject_references:
                ref_str = str(ref).strip()
                if ref_str:
                    self._add_obs_by_identifier(ref_str, obs)

            # Deep extraction of identifiers, resources, and aliases from facts and embedded JSON
            facts = obs.extracted_facts or {}
            found_idents: set[str] = set()
            found_resources: set[tuple[Optional[str], str]] = set()
            found_aliases: set[str] = set()
            _extract_identifiers_from_dict(facts, found_idents, found_resources, found_aliases)

            for ident in found_idents:
                self._add_obs_by_identifier(ident, obs)

            # Explicit observation resource
            r_id = obs.resource_id.strip() if obs.resource_id else None
            sys_id = obs.system_id.strip() if obs.system_id else None
            if r_id:
                found_resources.add((sys_id, r_id))

            for r_sys, r_val in found_resources:
                self.obs_by_resource.setdefault(r_val, []).append(obs)
                if r_sys:
                    self.obs_by_system_resource.setdefault((r_sys, r_val), []).append(obs)

            for alias_val in found_aliases:
                self.obs_by_alias.setdefault(alias_val, []).append(obs)

    def _add_obs_by_identifier(self, identifier: str, obs: EvidenceObservation) -> None:
        """Add an observation indexed under exact and normalized forms of an identifier."""
        raw = identifier.strip()
        if not raw:
            return
        # Store exact
        self.obs_by_identifier.setdefault(raw, []).append(obs)

        # Store normalized email or phone if applicable
        if "@" in raw:
            norm_email = normalize_email(raw)
            if norm_email and norm_email != raw:
                self.obs_by_identifier.setdefault(norm_email, []).append(obs)
        else:
            norm_phone = normalize_phone(raw)
            if norm_phone and norm_phone != raw:
                self.obs_by_identifier.setdefault(norm_phone, []).append(obs)

    def get_observations_for_identifier(
        self,
        identifier: str,
        cutoff: Optional[datetime] = None,
    ) -> list[EvidenceObservation]:
        """Lookup eligible observations matching an exact identifier at or before cutoff."""
        raw = identifier.strip()
        candidates = list(self.obs_by_identifier.get(raw, []))
        if "@" in raw:
            norm = normalize_email(raw)
            if norm:
                candidates.extend(self.obs_by_identifier.get(norm, []))
        else:
            norm = normalize_phone(raw)
            if norm:
                candidates.extend(self.obs_by_identifier.get(norm, []))

        results = _dedup_obs(candidates)
        if cutoff is not None:
            results = [o for o in results if o.capture_time <= cutoff]
        return sorted(results, key=lambda o: (o.evidence_id, o.capture_time, o.source_locator or ""))

    def get_observations_for_resource(
        self,
        system_id: Optional[str],
        resource_id: str,
        cutoff: Optional[datetime] = None,
    ) -> list[EvidenceObservation]:
        """Lookup observations matching a resource key at or before cutoff."""
        res_id = resource_id.strip()
        candidates: list[EvidenceObservation] = []
        if system_id and system_id != "unknown":
            candidates.extend(self.obs_by_system_resource.get((system_id.strip(), res_id), []))
        else:
            candidates.extend(self.obs_by_resource.get(res_id, []))
            candidates.extend(self.obs_by_alias.get(res_id, []))

        results = _dedup_obs(candidates)
        if cutoff is not None:
            results = [o for o in results if o.capture_time <= cutoff]
        return sorted(results, key=lambda o: (o.evidence_id, o.capture_time, o.source_locator or ""))

    def get_observations_for_alias(
        self,
        alias: str,
        cutoff: Optional[datetime] = None,
    ) -> list[EvidenceObservation]:
        """Lookup observations matching an external alias or filename at or before cutoff."""
        candidates = list(self.obs_by_alias.get(alias.strip(), []))
        candidates.extend(self.obs_by_resource.get(alias.strip(), []))
        results = _dedup_obs(candidates)
        if cutoff is not None:
            results = [o for o in results if o.capture_time <= cutoff]
        return sorted(results, key=lambda o: (o.evidence_id, o.capture_time, o.source_locator or ""))

    def get_catalog_links_for_subject(
        self,
        user_id: Optional[str],
        emails: Sequence[str] = (),
        cutoff: Optional[datetime] = None,
    ) -> list[CatalogLinkEntry]:
        """Lookup authoritative catalog links for a subject's user_id and emails at or before cutoff."""
        found: dict[str, CatalogLinkEntry] = {}
        if user_id:
            for entry in self.catalog_by_user_id.get(user_id.strip(), []):
                found[entry.activity_id] = entry
        for email in emails:
            norm = normalize_email(email)
            if norm:
                for entry in self.catalog_by_email.get(norm, []):
                    found[entry.activity_id] = entry

        results = list(found.values())
        if cutoff is not None:
            results = [e for e in results if e.event_time <= cutoff]
        return sorted(results, key=lambda e: (e.event_time, e.activity_id))

    def get_activities_for_resource(
        self,
        system_id: Optional[str],
        resource_id: str,
        cutoff: Optional[datetime] = None,
    ) -> list[SystemActivityEvent]:
        """Lookup system activity events acting on a grounded resource at or before cutoff."""
        res_id = resource_id.strip()
        candidates: list[SystemActivityEvent] = []
        if system_id and system_id != "unknown":
            candidates.extend(self.activity_by_system_resource.get((system_id.strip(), res_id), []))
        else:
            candidates.extend(self.activity_by_resource.get(res_id, []))

        results = _dedup_acts(candidates)
        if cutoff is not None:
            results = [a for a in results if a.event_time <= cutoff]
        return sorted(results, key=lambda a: (a.event_time, a.activity_id))

    def get_scoped_inventories(
        self,
        system_id: str,
        cutoff: Optional[datetime] = None,
    ) -> list[EvidenceObservation]:
        """Lookup scoped inventories for a system at or before cutoff."""
        results = self.inventories_by_system.get(system_id.strip(), [])
        if cutoff is not None:
            results = [o for o in results if o.capture_time <= cutoff]
        return sorted(results, key=lambda o: (o.evidence_id, o.capture_time, o.source_locator or ""))
