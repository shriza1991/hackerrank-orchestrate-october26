"""Evidence-grounded data category classifier."""

from __future__ import annotations

import re
from typing import Any, Optional

from ghost_audit.models.input_models import DataCategory
from ghost_audit.state.models import StateTimelineEvent


class GroundedCategoryClassifier:
    """Classifies resources and copies into authoritative DataCategory values.

    Keeps category identification strictly separate from rule evaluation.
    Grounds categories in schema, table, locator, explicit facts, content, and catalog relationships.
    Replaces invented synthetic categories with actual policy categories where justified.
    Leaves unknown or conflicting evidence unresolved (None).
    """

    @classmethod
    def classify(
        cls,
        system_id: str,
        resource_id: str,
        copy_type: Optional[str] = None,
        store_locator: Optional[str] = None,
        facts: Optional[dict[str, Any]] = None,
        timeline: Optional[list[StateTimelineEvent]] = None,
        existing_label: Optional[str] = None,
    ) -> tuple[Optional[DataCategory], str]:
        """Classify resource copy into an authoritative DataCategory.

        Returns (DataCategory, basis_description) or (None, unresolved_reason).
        """
        facts = facts or {}
        timeline = timeline or []
        signals: set[DataCategory] = set()
        bases: list[str] = []

        # 1. Check explicit attributes in facts
        explicit_cat = facts.get("data_category") or facts.get("category")
        if explicit_cat:
            try:
                cat = DataCategory(str(explicit_cat).strip())
                signals.add(cat)
                bases.append(f"Explicit fact data_category='{cat.value}'")
            except ValueError:
                pass

        explicit_type = str(facts.get("record_type") or "").lower()
        if explicit_type:
            if "tombstone" in explicit_type:
                signals.add(DataCategory.ACCOUNT_TOMBSTONE)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "profile" in explicit_type and "analytics" not in explicit_type and "marketing" not in explicit_type:
                signals.add(DataCategory.USER_PROFILE)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "secondary" in explicit_type or "alias" in explicit_type:
                signals.add(DataCategory.SECONDARY_IDENTIFIER)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "audit" in explicit_type or "security" in explicit_type:
                signals.add(DataCategory.SECURITY_AUDIT_LOG)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "hold" in explicit_type:
                signals.add(DataCategory.LEGAL_HOLD_RECORD)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "delivery" in explicit_type or "email_log" in explicit_type:
                signals.add(DataCategory.EMAIL_DELIVERY_LOG)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "attachment" in explicit_type:
                signals.add(DataCategory.SUPPORT_ATTACHMENT)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "message" in explicit_type or "ticket" in explicit_type:
                signals.add(DataCategory.SUPPORT_MESSAGE)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "export" in explicit_type:
                signals.add(DataCategory.USER_EXPORT)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "telemetry" in explicit_type or "event" in explicit_type:
                signals.add(DataCategory.PRODUCT_TELEMETRY)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "analytics" in explicit_type:
                signals.add(DataCategory.ANALYTICS_PROFILE)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "marketing" in explicit_type:
                signals.add(DataCategory.MARKETING_PROFILE)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "cache" in explicit_type:
                signals.add(DataCategory.CACHE_ENTRY)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "search" in explicit_type:
                signals.add(DataCategory.SEARCH_INDEX_ENTRY)
                bases.append(f"Explicit record_type='{explicit_type}'")
            elif "backup" in explicit_type:
                signals.add(DataCategory.BACKUP_ARCHIVE)
                bases.append(f"Explicit record_type='{explicit_type}'")

        # 2. Check table name / locator
        table_name = str(facts.get("table_name") or store_locator or "").lower()
        if "customer_profiles" in table_name or "user_accounts" in table_name or "profiles" in table_name:
            if "tombstone" in resource_id.lower() or "tombstone" in table_name:
                signals.add(DataCategory.ACCOUNT_TOMBSTONE)
                bases.append(f"Tombstone identifier in table '{table_name}'")
            else:
                signals.add(DataCategory.USER_PROFILE)
                bases.append(f"User profile table '{table_name}'")
        elif "account_tombstones" in table_name or "tombstone" in table_name:
            signals.add(DataCategory.ACCOUNT_TOMBSTONE)
            bases.append(f"Account tombstone table '{table_name}'")
        elif "secondary_identit" in table_name or "user_aliases" in table_name:
            signals.add(DataCategory.SECONDARY_IDENTIFIER)
            bases.append(f"Secondary identifier table '{table_name}'")
        elif "email_delivery" in table_name or "delivery_log" in table_name or "mail_log" in table_name:
            signals.add(DataCategory.EMAIL_DELIVERY_LOG)
            bases.append(f"Email delivery log table '{table_name}'")
        elif "security_audit" in table_name or "audit_log" in table_name or "audit_record" in table_name:
            signals.add(DataCategory.SECURITY_AUDIT_LOG)
            bases.append(f"Security audit log table '{table_name}'")
        elif "legal_hold" in table_name:
            signals.add(DataCategory.LEGAL_HOLD_RECORD)
            bases.append(f"Legal hold table '{table_name}'")
        elif "support_attachment" in table_name:
            signals.add(DataCategory.SUPPORT_ATTACHMENT)
            bases.append(f"Support attachment table '{table_name}'")
        elif "support_ticket" in table_name or "ticket_message" in table_name:
            signals.add(DataCategory.SUPPORT_MESSAGE)
            bases.append(f"Support message table '{table_name}'")
        elif "analytics_profile" in table_name or "customer_traits" in table_name:
            signals.add(DataCategory.ANALYTICS_PROFILE)
            bases.append(f"Analytics profile table '{table_name}'")
        elif "telemetry" in table_name or "product_event" in table_name:
            signals.add(DataCategory.PRODUCT_TELEMETRY)
            bases.append(f"Product telemetry table '{table_name}'")
        elif "user_export" in table_name or "export_archive" in table_name:
            signals.add(DataCategory.USER_EXPORT)
            bases.append(f"User export store '{table_name}'")
        elif "marketing_profile" in table_name or "subscribers" in table_name:
            signals.add(DataCategory.MARKETING_PROFILE)
            bases.append(f"Marketing profile store '{table_name}'")
        elif "search_index" in table_name or "search_doc" in table_name:
            signals.add(DataCategory.SEARCH_INDEX_ENTRY)
            bases.append(f"Search index store '{table_name}'")
        elif "cache_store" in table_name or "redis" in table_name:
            signals.add(DataCategory.CACHE_ENTRY)
            bases.append(f"Cache store '{table_name}'")
        elif "backup_archive" in table_name or "backup_snapshot" in table_name:
            signals.add(DataCategory.BACKUP_ARCHIVE)
            bases.append(f"Backup archive store '{table_name}'")

        # 3. Grounded system & resource naming patterns
        r_lower = resource_id.lower()
        sys_lower = system_id.lower()

        if r_lower.startswith("tombstone_") or "tombstone" in r_lower:
            signals.add(DataCategory.ACCOUNT_TOMBSTONE)
            bases.append(f"Tombstone resource identity '{resource_id}'")
        elif r_lower.startswith("audit_record_") or sys_lower == "security_service":
            signals.add(DataCategory.SECURITY_AUDIT_LOG)
            bases.append(f"Security audit resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("search_") or sys_lower == "search_service":
            signals.add(DataCategory.SEARCH_INDEX_ENTRY)
            bases.append(f"Search index resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("export_") or sys_lower == "export_service":
            signals.add(DataCategory.USER_EXPORT)
            bases.append(f"User export resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("backup_") or sys_lower == "backup_service":
            signals.add(DataCategory.BACKUP_ARCHIVE)
            bases.append(f"Backup archive resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("support_") or sys_lower == "support_platform":
            # Distinguish support message vs support attachment
            is_attachment = (
                "attachment" in r_lower
                or "attachment" in str(store_locator).lower()
                or facts.get("is_attachment") is True
                or any(ext in str(facts.get("file_name", "")).lower() for ext in [".pdf", ".png", ".jpg", ".csv", ".docx"])
            )
            if is_attachment:
                signals.add(DataCategory.SUPPORT_ATTACHMENT)
                bases.append(f"Support attachment '{resource_id}' in '{system_id}'")
            else:
                signals.add(DataCategory.SUPPORT_MESSAGE)
                bases.append(f"Support message conversation '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("analytics_") or sys_lower == "analytics_platform":
            # Distinguish analytics profile vs product telemetry
            is_telemetry = (
                "event" in r_lower
                or "telemetry" in r_lower
                or "click" in r_lower
                or facts.get("event_type") is not None
                or "telemetry" in table_name
            )
            if is_telemetry:
                signals.add(DataCategory.PRODUCT_TELEMETRY)
                bases.append(f"Product telemetry event '{resource_id}' in '{system_id}'")
            else:
                signals.add(DataCategory.ANALYTICS_PROFILE)
                bases.append(f"Analytics user profile '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("account_") or sys_lower == "account_service":
            if "tombstone" in r_lower:
                signals.add(DataCategory.ACCOUNT_TOMBSTONE)
                bases.append(f"Account tombstone '{resource_id}' in '{system_id}'")
            else:
                signals.add(DataCategory.USER_PROFILE)
                bases.append(f"User profile resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("marketing_") or sys_lower == "marketing_service":
            signals.add(DataCategory.MARKETING_PROFILE)
            bases.append(f"Marketing profile resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("delivery_") or sys_lower == "email_service":
            signals.add(DataCategory.EMAIL_DELIVERY_LOG)
            bases.append(f"Email delivery log resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("hold_") or sys_lower == "legal_hold_service":
            signals.add(DataCategory.LEGAL_HOLD_RECORD)
            bases.append(f"Legal hold resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("cache_") or sys_lower == "cache_service":
            signals.add(DataCategory.CACHE_ENTRY)
            bases.append(f"Cache entry resource '{resource_id}' in '{system_id}'")
        elif r_lower.startswith("secondary_") or r_lower.startswith("alias_"):
            signals.add(DataCategory.SECONDARY_IDENTIFIER)
            bases.append(f"Secondary identifier resource '{resource_id}'")

        # 4. Synthesize signals
        if len(signals) == 1:
            category = next(iter(signals))
            basis_str = "; ".join(bases)
            return category, basis_str
        elif len(signals) > 1:
            # Check if there is a conflict or hierarchical refinement
            # e.g. tombstone is a refinement of user profile
            if DataCategory.ACCOUNT_TOMBSTONE in signals and DataCategory.USER_PROFILE in signals:
                return DataCategory.ACCOUNT_TOMBSTONE, f"Account tombstone refinement over profile ({'; '.join(bases)})"
            if DataCategory.SUPPORT_ATTACHMENT in signals and DataCategory.SUPPORT_MESSAGE in signals:
                return DataCategory.SUPPORT_ATTACHMENT, f"Attachment document distinction over message context ({'; '.join(bases)})"
            if DataCategory.PRODUCT_TELEMETRY in signals and DataCategory.ANALYTICS_PROFILE in signals:
                return DataCategory.PRODUCT_TELEMETRY, f"Telemetry event distinction over analytics profile ({'; '.join(bases)})"

            # Irreconcilable conflict: must remain unresolved
            conflict_names = sorted(s.value for s in signals)
            return None, f"Conflicting category evidence detected: {', '.join(conflict_names)} ({'; '.join(bases)})"

        # No signals matched
        return None, f"Unresolved category for system='{system_id}', resource='{resource_id}': insufficient grounded evidence"
