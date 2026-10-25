"""Evidence linking engine implementing exact matching, catalog links, and controlled expansion."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Optional, Sequence

from ghost_audit.identity.normalization import normalize_email, normalize_phone
from ghost_audit.models.intermediate_models import (
    EvidenceObservation,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from ghost_audit.retrieval.index import CatalogLinkEntry, CorpusIndex
from ghost_audit.retrieval.models import (
    AmbiguousOrRejectedLink,
    EvidenceLink,
    LinkEndpoint,
    LinkProvenance,
    LinkRelationship,
    ResourceKey,
    RetrievalDiagnostics,
    ScopedInventory,
    SelectedActivity,
    SelectedObservation,
)


class EvidenceLinker:
    """Core deterministic linking algorithm connecting a subject to evidence and activity."""

    def __init__(self, index: CorpusIndex, max_depth: int = 5) -> None:
        self.index = index
        self.max_depth = max_depth

    def link_case(
        self,
        case_id: str,
        audit_at: datetime,
        identity_result: IdentityResolutionResult,
        failed_files: Sequence[str] = (),
        deferred_files: Sequence[str] = (),
        manifest_errors: Sequence[str] = (),
    ) -> tuple[
        list[SelectedObservation],
        list[SelectedActivity],
        list[ScopedInventory],
        list[EvidenceLink],
        list[str],  # grounded_resource_keys
        list[AmbiguousOrRejectedLink],
        RetrievalDiagnostics,
    ]:
        start_time = time.perf_counter()

        # Subject identifiers
        user_id = identity_result.stable_subject_reference
        subject_identifiers = self._extract_subject_identifiers(identity_result)

        selected_obs_map: dict[str, SelectedObservation] = {}
        selected_acts_map: dict[str, SelectedActivity] = {}
        links: list[EvidenceLink] = []
        grounded_resources: dict[str, ResourceKey] = {}  # str_key -> ResourceKey
        grounded_aliases: set[str] = set()
        rejected_links: list[AmbiguousOrRejectedLink] = []
        coverage_warnings: list[str] = []
        cycles_detected: list[str] = []

        link_counter = 0

        def next_link_id() -> str:
            nonlocal link_counter
            link_counter += 1
            return f"link_{link_counter:04d}"

        # -------------------------------------------------------------
        # Phase 1: Authoritative Catalog Links (LINK_RESOURCE_IDENTITY)
        # -------------------------------------------------------------
        all_catalog_entries = self.index.get_catalog_links_for_subject(
            user_id=user_id,
            emails=subject_identifiers["emails"],
            cutoff=None,
        )
        catalog_entries = []
        for cat in all_catalog_entries:
            if cat.event_time > audit_at:
                rejected_links.append(
                    AmbiguousOrRejectedLink(
                        candidate_endpoint=f"resource:{cat.canonical_resource_id}",
                        source_id=cat.activity_id,
                        reason=f"FUTURE_TIMESTAMP_EXCLUDED: Catalog event time {cat.event_time.isoformat()} exceeds audit cutoff {audit_at.isoformat()}.",
                        details={"canonical_resource_id": cat.canonical_resource_id, "event_time": cat.event_time.isoformat()},
                    )
                )
            else:
                catalog_entries.append(cat)

        for cat in catalog_entries:
            res_key = ResourceKey(system_id=cat.target_system, resource_id=cat.canonical_resource_id)
            res_key_str = str(res_key)
            grounded_resources[res_key_str] = res_key

            link = EvidenceLink(
                link_id=next_link_id(),
                from_endpoint=LinkEndpoint(endpoint_type="SUBJECT", endpoint_id=user_id or "unknown"),
                to_endpoint=LinkEndpoint(endpoint_type="RESOURCE", endpoint_id=res_key_str),
                provenance=LinkProvenance(
                    source_type="DATA_CATALOG",
                    source_id=cat.activity_id,
                    timestamp=cat.event_time,
                    relationship=LinkRelationship.CATALOG_RESOURCE_IDENTITY,
                    is_direct=True,
                ),
                explanation=f"Catalog event {cat.activity_id} explicitly linked {cat.canonical_resource_id} to subject",
            )
            links.append(link)

            if cat.external_alias and cat.external_alias != cat.canonical_resource_id:
                grounded_aliases.add(cat.external_alias)
                alias_link = EvidenceLink(
                    link_id=next_link_id(),
                    from_endpoint=LinkEndpoint(endpoint_type="RESOURCE", endpoint_id=res_key_str),
                    to_endpoint=LinkEndpoint(endpoint_type="ALIAS", endpoint_id=cat.external_alias),
                    provenance=LinkProvenance(
                        source_type="DATA_CATALOG",
                        source_id=cat.activity_id,
                        timestamp=cat.event_time,
                        relationship=LinkRelationship.CATALOG_EXTERNAL_ALIAS,
                        is_direct=True,
                    ),
                    explanation=f"Catalog event {cat.activity_id} established display/attachment alias '{cat.external_alias}'",
                )
                links.append(alias_link)

        # -------------------------------------------------------------
        # Phase 2: Direct Identifier Matching in Eligible Observations
        # -------------------------------------------------------------
        for ident in subject_identifiers["all"]:
            all_raw_obs = self.index.get_observations_for_identifier(ident, cutoff=None)
            raw_obs_list = []
            for obs in all_raw_obs:
                if obs.capture_time > audit_at or (obs.observation_time and obs.observation_time > audit_at):
                    rejected_links.append(
                        AmbiguousOrRejectedLink(
                            candidate_endpoint=f"observation:{obs.evidence_id}:{obs.source_locator or ''}",
                            source_id=obs.evidence_id,
                            reason=f"FUTURE_TIMESTAMP_EXCLUDED: Observation time exceeds audit cutoff {audit_at.isoformat()}.",
                            details={"matched_identifier": ident, "capture_time": obs.capture_time.isoformat()},
                        )
                    )
                else:
                    raw_obs_list.append(obs)

            for obs in raw_obs_list:
                # Check for cross-user collision / leakage
                obs_user_id = obs.extracted_facts.get("user_id") or (
                    obs.subject_references[0] if obs.subject_references and obs.subject_references[0].startswith("user_") else None
                )
                if obs_user_id and user_id and obs_user_id != user_id:
                    rejected_links.append(
                        AmbiguousOrRejectedLink(
                            candidate_endpoint=f"observation:{obs.evidence_id}:{obs.source_locator}",
                            source_id=obs.evidence_id,
                            reason=f"CROSS_USER_CONFLICT: Observation contains user_id '{obs_user_id}' differing from subject '{user_id}'.",
                            details={"matched_identifier": ident, "obs_user_id": obs_user_id, "subject_user_id": user_id},
                        )
                    )
                    continue

                obs_key = f"{obs.evidence_id}:{obs.source_locator or ''}"
                link = EvidenceLink(
                    link_id=next_link_id(),
                    from_endpoint=LinkEndpoint(endpoint_type="IDENTIFIER", endpoint_id=ident),
                    to_endpoint=LinkEndpoint(endpoint_type="OBSERVATION", endpoint_id=obs_key),
                    provenance=LinkProvenance(
                        source_type="EVIDENCE_OBSERVATION",
                        source_id=obs.evidence_id,
                        source_locator=obs.source_locator,
                        timestamp=obs.capture_time,
                        relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
                        is_direct=True,
                    ),
                    explanation=f"Observation in {obs.evidence_id} matched subject identifier '{ident}'",
                )
                links.append(link)

                # Ground the observation's resource if present
                obs_grounded_res: list[str] = []
                if obs.resource_id:
                    sys_id = obs.system_id or "unknown"
                    r_key = ResourceKey(system_id=sys_id, resource_id=obs.resource_id, source_locator=obs.source_locator)
                    r_str = str(r_key)
                    grounded_resources[r_str] = r_key
                    obs_grounded_res.append(r_str)

                if obs_key not in selected_obs_map:
                    selected_obs_map[obs_key] = SelectedObservation(
                        observation=obs,
                        matched_identifiers=[ident],
                        grounded_resources=obs_grounded_res,
                        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
                        supporting_links=[link],
                    )
                else:
                    curr = selected_obs_map[obs_key]
                    if ident not in curr.matched_identifiers:
                        curr.matched_identifiers.append(ident)
                    for r in obs_grounded_res:
                        if r not in curr.grounded_resources:
                            curr.grounded_resources.append(r)
                    curr.supporting_links.append(link)

        # -------------------------------------------------------------
        # Phase 3: Iterative Controlled Link Expansion
        # -------------------------------------------------------------
        depth = 0
        visited_resources: set[str] = set()
        visited_aliases: set[str] = set()

        while depth < self.max_depth:
            depth += 1
            new_res_to_visit = [r for r in grounded_resources.keys() if r not in visited_resources]
            new_aliases_to_visit = [a for a in grounded_aliases if a not in visited_aliases]

            if not new_res_to_visit and not new_aliases_to_visit:
                break

            # Expand aliases
            for alias in new_aliases_to_visit:
                visited_aliases.add(alias)
                alias_obs_list = self.index.get_observations_for_alias(alias, cutoff=audit_at)
                for obs in alias_obs_list:
                    obs_key = f"{obs.evidence_id}:{obs.source_locator or ''}"
                    link = EvidenceLink(
                        link_id=next_link_id(),
                        from_endpoint=LinkEndpoint(endpoint_type="ALIAS", endpoint_id=alias),
                        to_endpoint=LinkEndpoint(endpoint_type="OBSERVATION", endpoint_id=obs_key),
                        provenance=LinkProvenance(
                            source_type="EVIDENCE_OBSERVATION",
                            source_id=obs.evidence_id,
                            source_locator=obs.source_locator,
                            timestamp=obs.capture_time,
                            relationship=LinkRelationship.CATALOG_EXTERNAL_ALIAS,
                            is_direct=False,
                        ),
                        explanation=f"Observation in {obs.evidence_id} matched catalog alias '{alias}'",
                    )
                    links.append(link)

                    obs_grounded_res = []
                    if obs.resource_id:
                        sys_id = obs.system_id or "unknown"
                        r_key = ResourceKey(system_id=sys_id, resource_id=obs.resource_id, source_locator=obs.source_locator)
                        r_str = str(r_key)
                        if r_str not in grounded_resources:
                            grounded_resources[r_str] = r_key
                        obs_grounded_res.append(r_str)

                    if obs_key not in selected_obs_map:
                        selected_obs_map[obs_key] = SelectedObservation(
                            observation=obs,
                            matched_identifiers=[],
                            grounded_resources=obs_grounded_res,
                            primary_relationship=LinkRelationship.CATALOG_EXTERNAL_ALIAS,
                            supporting_links=[link],
                        )

            # Expand resources
            for r_str in new_res_to_visit:
                visited_resources.add(r_str)
                r_key = grounded_resources[r_str]

                res_obs_list = self.index.get_observations_for_resource(
                    system_id=r_key.system_id if r_key.system_id != "unknown" else None,
                    resource_id=r_key.resource_id,
                    cutoff=audit_at,
                )
                for obs in res_obs_list:
                    obs_key = f"{obs.evidence_id}:{obs.source_locator or ''}"
                    link = EvidenceLink(
                        link_id=next_link_id(),
                        from_endpoint=LinkEndpoint(endpoint_type="RESOURCE", endpoint_id=r_str),
                        to_endpoint=LinkEndpoint(endpoint_type="OBSERVATION", endpoint_id=obs_key),
                        provenance=LinkProvenance(
                            source_type="EVIDENCE_OBSERVATION",
                            source_id=obs.evidence_id,
                            source_locator=obs.source_locator,
                            timestamp=obs.capture_time,
                            relationship=LinkRelationship.OBSERVATION_RESOURCE_CHAIN,
                            is_direct=False,
                        ),
                        explanation=f"Observation in {obs.evidence_id} linked via resource {r_str}",
                    )
                    links.append(link)

                    obs_res_str = r_str
                    if obs.system_id and obs.resource_id:
                        actual_key = ResourceKey(system_id=obs.system_id, resource_id=obs.resource_id, source_locator=obs.source_locator)
                        actual_key_str = str(actual_key)
                        grounded_resources[actual_key_str] = actual_key
                        obs_res_str = actual_key_str

                    if obs_key not in selected_obs_map:
                        selected_obs_map[obs_key] = SelectedObservation(
                            observation=obs,
                            matched_identifiers=[],
                            grounded_resources=[obs_res_str],
                            primary_relationship=LinkRelationship.OBSERVATION_RESOURCE_CHAIN,
                            supporting_links=[link],
                        )
                    else:
                        if obs_res_str not in selected_obs_map[obs_key].grounded_resources:
                            selected_obs_map[obs_key].grounded_resources.append(obs_res_str)
                        selected_obs_map[obs_key].supporting_links.append(link)

                    # Extract chained resources
                    facts = obs.extracted_facts or {}
                    linked_res = facts.get("linked_resources") or []
                    if isinstance(linked_res, list):
                        for chained_r in linked_res:
                            chained_str = str(chained_r).strip()
                            if chained_str:
                                # When system is not specified in the reference, leave system as unknown
                                # to be grounded by the actual store observation
                                chained_key = ResourceKey(system_id="unknown", resource_id=chained_str)
                                chained_key_str = str(chained_key)
                                if (
                                    chained_key_str in grounded_resources
                                    or any(k.endswith(f":{chained_str}") for k in grounded_resources)
                                    or any(r_k.resource_id == chained_str for r_k in grounded_resources.values())
                                ):
                                    cycles_detected.append(f"{r_str} -> {chained_key_str}")
                                else:
                                    grounded_resources[chained_key_str] = chained_key

        if depth >= self.max_depth:
            coverage_warnings.append(f"Reached maximum link expansion depth limit ({self.max_depth}).")

        # -------------------------------------------------------------
        # Phase 4: Relevant Pre-Cutoff System Activity Matching
        # -------------------------------------------------------------
        for r_str, r_key in grounded_resources.items():
            all_activities = self.index.get_activities_for_resource(
                system_id=r_key.system_id if r_key.system_id != "unknown" else None,
                resource_id=r_key.resource_id,
                cutoff=None,
            )
            activities = []
            for act in all_activities:
                if act.event_time > audit_at:
                    rejected_links.append(
                        AmbiguousOrRejectedLink(
                            candidate_endpoint=f"activity:{act.activity_id}",
                            source_id=act.activity_id,
                            reason=f"FUTURE_TIMESTAMP_EXCLUDED: Activity event time {act.event_time.isoformat()} exceeds audit cutoff {audit_at.isoformat()}.",
                            details={"activity_id": act.activity_id, "event_time": act.event_time.isoformat(), "resource_id": act.resource_id},
                        )
                    )
                else:
                    activities.append(act)
            for act in activities:
                link = EvidenceLink(
                    link_id=next_link_id(),
                    from_endpoint=LinkEndpoint(endpoint_type="RESOURCE", endpoint_id=r_str),
                    to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id=act.activity_id),
                    provenance=LinkProvenance(
                        source_type="SYSTEM_ACTIVITY",
                        source_id=act.activity_id,
                        timestamp=act.event_time,
                        relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                        is_direct=True,
                    ),
                    explanation=f"Activity {act.activity_id} performed {act.event_type} on grounded resource {r_key.resource_id}",
                )
                links.append(link)

                rep_res = act.reported_result.value if hasattr(act.reported_result, "value") else str(act.reported_result)
                selected_acts_map[act.activity_id] = SelectedActivity(
                    activity_id=act.activity_id,
                    event_time=act.event_time,
                    event_type=act.event_type,
                    source_system=act.source_system,
                    target_system=act.target_system,
                    resource_id=act.resource_id,
                    reported_result=rep_res,
                    details=act.details,
                    grounded_resource_key=r_str,
                    supporting_link=link,
                )

        # -------------------------------------------------------------
        # Phase 5: Relevant Scoped Inventories
        # -------------------------------------------------------------
        systems_involved = {r_key.system_id for r_key in grounded_resources.values() if r_key.system_id != "unknown"}
        # Always include primary/failover account stores if an account or user was involved
        if user_id or any("account" in s for s in systems_involved):
            systems_involved.add("account_service")

        scoped_inventories: list[ScopedInventory] = []
        for sys_id in sorted(systems_involved):
            inv_obs_list = self.index.get_scoped_inventories(sys_id, cutoff=audit_at)
            for inv_obs in inv_obs_list:
                scoped_inventories.append(
                    ScopedInventory(
                        system_id=sys_id,
                        resource_id=inv_obs.resource_id,
                        source_id=inv_obs.evidence_id,
                        source_locator=inv_obs.source_locator,
                        timestamp=inv_obs.capture_time,
                        scope_context=inv_obs.scope_context,
                        extracted_facts=inv_obs.extracted_facts,
                    )
                )

        # -------------------------------------------------------------
        # Phase 6: Deterministic Diagnostics & Sorting
        # -------------------------------------------------------------
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Calculate counts
        total_eligible_obs = sum(1 for o in self.index.observations if o.capture_time <= audit_at)
        total_future_obs = len(self.index.observations) - total_eligible_obs
        total_eligible_acts = sum(1 for a in self.index.activity_events if a.event_time <= audit_at)
        total_future_acts = len(self.index.activity_events) - total_eligible_acts

        scope = "KNOWN_COMPLETE"
        if failed_files or manifest_errors or depth >= self.max_depth:
            scope = "KNOWN_INCOMPLETE"
        elif deferred_files:
            scope = "KNOWN_INCOMPLETE"

        diagnostics = RetrievalDiagnostics(
            case_id=case_id,
            audit_at=audit_at,
            total_eligible_observations_scanned=total_eligible_obs,
            total_future_observations_excluded=total_future_obs,
            total_eligible_activities_scanned=total_eligible_acts,
            total_future_activities_excluded=total_future_acts,
            max_expansion_depth_reached=depth,
            cycles_detected=sorted(list(set(cycles_detected))),
            coverage_warnings=coverage_warnings,
            coverage_scope=scope,
            failed_files=list(failed_files),
            deferred_files=list(deferred_files),
            manifest_errors=list(manifest_errors),
            execution_time_ms=elapsed_ms,
        )

        sorted_obs = sorted(
            selected_obs_map.values(),
            key=lambda so: (so.observation.evidence_id, so.observation.capture_time, so.observation.source_locator or ""),
        )
        sorted_acts = sorted(
            selected_acts_map.values(),
            key=lambda sa: (sa.event_time, sa.activity_id),
        )
        sorted_inv = sorted(
            scoped_inventories,
            key=lambda si: (si.timestamp, si.source_id, si.system_id, si.source_locator or ""),
        )
        sorted_links = sorted(links, key=lambda l: l.link_id)
        sorted_grounded_res = sorted(list(grounded_resources.keys()))
        sorted_rejected = sorted(rejected_links, key=lambda r: (r.candidate_endpoint, r.source_id))

        return (
            sorted_obs,
            sorted_acts,
            sorted_inv,
            sorted_links,
            sorted_grounded_res,
            sorted_rejected,
            diagnostics,
        )

    def _extract_subject_identifiers(self, result: IdentityResolutionResult) -> dict[str, list[str]]:
        """Extract and categorize all supported exact and normalized subject identifiers."""
        emails: set[str] = set()
        phones: set[str] = set()
        hashes: set[str] = set()
        all_idents: set[str] = set()

        if result.stable_subject_reference:
            all_idents.add(result.stable_subject_reference)

        # Current
        curr = result.current_identifiers or {}
        if curr.get("email"):
            norm = normalize_email(curr["email"])
            if norm:
                emails.add(norm)
                all_idents.add(norm)
        if curr.get("phone"):
            norm = normalize_phone(curr["phone"])
            if norm:
                phones.add(norm)
                all_idents.add(norm)
        if curr.get("email_hash"):
            hashes.add(curr["email_hash"])
            all_idents.add(curr["email_hash"])

        # Historical
        for hist in result.historical_identifiers:
            if hist.get("email"):
                norm = normalize_email(hist["email"])
                if norm:
                    emails.add(norm)
                    all_idents.add(norm)
            if hist.get("phone"):
                norm = normalize_phone(hist["phone"])
                if norm:
                    phones.add(norm)
                    all_idents.add(norm)
            if hist.get("email_hash"):
                hashes.add(hist["email_hash"])
                all_idents.add(hist["email_hash"])

        # Request email
        if result.request_email:
            norm = normalize_email(result.request_email)
            if norm:
                emails.add(norm)
                all_idents.add(norm)

        for s in result.searchable_identifiers:
            if s:
                all_idents.add(s)

        return {
            "emails": sorted(list(emails)),
            "phones": sorted(list(phones)),
            "hashes": sorted(list(hashes)),
            "all": sorted(list(all_idents)),
        }
