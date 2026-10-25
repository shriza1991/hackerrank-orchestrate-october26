"""Evidence manifest validation and disk checks."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from ghost_audit.models.input_models import EvidenceManifestEntry


@dataclass
class ManifestValidationResult:
    """Outcome of validating the evidence manifest against files on disk."""

    total_entries: int = 0
    unique_ids: int = 0
    valid_files: int = 0
    extension_counts: dict[str, int] = field(default_factory=dict)
    duplicate_ids: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    path_traversal_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0 and len(self.missing_files) == 0 and len(self.path_traversal_errors) == 0


def validate_evidence_manifest(
    entries: Sequence[EvidenceManifestEntry],
    dataset_dir: Path,
) -> ManifestValidationResult:
    """Validate evidence manifest entries against the disk filesystem.

    Checks:
    - Evidence IDs are unique.
    - Each file path resolves strictly within dataset/evidence/ (no path traversal).
    - Each referenced file exists and is a regular file.
    - Collects file extension counts.
    """
    result = ManifestValidationResult(total_entries=len(entries))
    evidence_root = (dataset_dir / "evidence").resolve()

    seen_ids: set[str] = set()
    extensions: Counter[str] = Counter()

    for entry in entries:
        # Check duplicate IDs
        if entry.file_id in seen_ids:
            msg = f"Duplicate file_id '{entry.file_id}' in manifest."
            result.duplicate_ids.append(entry.file_id)
            result.errors.append(msg)
        else:
            seen_ids.add(entry.file_id)

        # Resolve path
        # file_path in evidence_files.csv is like "evidence/logs/..."
        # So resolving relative to dataset_dir gives dataset/evidence/logs/...
        resolved = (dataset_dir / entry.file_path).resolve()

        # Path traversal check: must stay under evidence_root
        try:
            resolved.relative_to(evidence_root)
        except ValueError:
            msg = f"Path traversal error for file_id '{entry.file_id}': '{entry.file_path}' resolves outside {evidence_root}"
            result.path_traversal_errors.append(msg)
            result.errors.append(msg)
            continue

        # File existence check
        if not resolved.is_file():
            msg = f"Evidence file missing on disk: '{entry.file_path}' (resolved: '{resolved}')"
            result.missing_files.append(msg)
            result.errors.append(msg)
            continue

        result.valid_files += 1
        ext = resolved.suffix.lower()
        extensions[ext] += 1

    result.unique_ids = len(seen_ids)
    result.extension_counts = dict(sorted(extensions.items()))
    return result
