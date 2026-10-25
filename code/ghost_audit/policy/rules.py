"""Policy rule catalog loading, validation, and indexing."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional

from ghost_audit.models.input_models import DataCategory, DeletionRule, RequiredAction


class PolicyRuleCatalogError(Exception):
    """Exception raised when policy rules are missing, duplicate, conflicting, or unsupported."""

    def __init__(self, message: str, issues: Optional[list[str]] = None) -> None:
        super().__init__(message)
        self.issues = issues or []


class PolicyRuleCatalog:
    """Catalog of authoritative deletion rules loaded and validated from dataset/deletion_rules.csv."""

    def __init__(self, rules: list[DeletionRule]) -> None:
        self._rules_by_category: dict[DataCategory, DeletionRule] = {}
        self._rules_by_id: dict[str, DeletionRule] = {}
        self._validate_and_index(rules)

    def _validate_and_index(self, rules: list[DeletionRule]) -> None:
        issues: list[str] = []
        seen_ids: set[str] = set()

        for rule in rules:
            # Check duplicate rule_id
            if rule.rule_id in seen_ids:
                issues.append(f"Duplicate rule_id detected: '{rule.rule_id}'")
            seen_ids.add(rule.rule_id)

            # Check duplicate / conflicting category rule
            if rule.data_category in self._rules_by_category:
                existing = self._rules_by_category[rule.data_category]
                issues.append(
                    f"Conflicting rule for category '{rule.data_category.value}': "
                    f"'{rule.rule_id}' conflicts with existing '{existing.rule_id}'"
                )
            else:
                self._rules_by_category[rule.data_category] = rule

            self._rules_by_id[rule.rule_id] = rule

        # Check missing categories from standard DataCategory enum
        expected_categories = set(DataCategory)
        present_categories = set(self._rules_by_category.keys())
        missing_categories = expected_categories - present_categories
        if missing_categories:
            missing_names = sorted(c.value for c in missing_categories)
            issues.append(f"Missing required policy rules for categories: {', '.join(missing_names)}")

        if issues:
            raise PolicyRuleCatalogError(
                f"Policy rule catalog validation failed with {len(issues)} issue(s): {'; '.join(issues)}",
                issues=issues,
            )

    @classmethod
    def load_from_csv(cls, path: Path) -> PolicyRuleCatalog:
        """Load and strictly validate deletion rules from CSV file."""
        if not path.exists():
            raise PolicyRuleCatalogError(f"Policy rules file not found: {path}")

        rules: list[DeletionRule] = []
        issues: list[str] = []

        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            required_cols = {"rule_id", "data_category", "condition", "required_action"}
            if not reader.fieldnames or not required_cols.issubset(set(reader.fieldnames)):
                raise PolicyRuleCatalogError(
                    f"Policy rules file missing required headers: {required_cols - set(reader.fieldnames or [])}"
                )

            for idx, row in enumerate(reader, start=2):
                rule_id = (row.get("rule_id") or "").strip()
                cat_str = (row.get("data_category") or "").strip()
                condition = (row.get("condition") or "").strip()
                action_str = (row.get("required_action") or "").strip()

                if not rule_id or not cat_str or not condition or not action_str:
                    issues.append(f"Row {idx}: missing required field(s)")
                    continue

                try:
                    category = DataCategory(cat_str)
                except ValueError:
                    issues.append(f"Row {idx}: unsupported data category '{cat_str}'")
                    continue

                try:
                    action = RequiredAction(action_str)
                except ValueError:
                    issues.append(f"Row {idx}: unsupported required action '{action_str}'")
                    continue

                rules.append(
                    DeletionRule(
                        rule_id=rule_id,
                        data_category=category,
                        condition=condition,
                        required_action=action,
                    )
                )

        if issues:
            raise PolicyRuleCatalogError(
                f"Failed to parse policy rules CSV: {len(issues)} issue(s)",
                issues=issues,
            )

        return cls(rules)

    def get_rule(self, category: DataCategory) -> DeletionRule:
        """Retrieve authoritative rule for a data category. Never silently falls back."""
        if category not in self._rules_by_category:
            raise PolicyRuleCatalogError(f"No deletion rule defined for data category '{category.value}'")
        return self._rules_by_category[category]

    def get_rule_by_id(self, rule_id: str) -> Optional[DeletionRule]:
        """Retrieve rule by rule_id."""
        return self._rules_by_id.get(rule_id)

    def all_rules(self) -> list[DeletionRule]:
        """Return all validated deletion rules."""
        return list(self._rules_by_id.values())
