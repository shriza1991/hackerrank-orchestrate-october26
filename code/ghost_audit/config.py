"""Configuration and path resolution for ghost_audit."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Resolve default dataset path relative to this file's location (repository root / dataset)
# code/ghost_audit/config.py -> parents[2] is the repository root
PACKAGE_ROOT = Path(__file__).resolve().parent
CODE_ROOT = PACKAGE_ROOT.parent
REPO_ROOT = CODE_ROOT.parent
DEFAULT_DATASET_PATH = REPO_ROOT / "dataset"

# Expected counts for dataset validation verification
EXPECTED_COUNTS = {
    "evaluation_requests": 518,
    "sample_requests": 32,
    "identities": 850,
    "historical_changes": 306,
    "activity_events": 4011,
    "policy_rules": 15,
    "evidence_files": 94,
}


@dataclass(frozen=True)
class Settings:
    """Settings with path resolution for data files."""

    dataset_dir: Path = DEFAULT_DATASET_PATH

    def __post_init__(self) -> None:
        # Normalize and resolve path
        object.__setattr__(self, "dataset_dir", Path(self.dataset_dir).resolve())

    @property
    def deletion_requests_path(self) -> Path:
        return self.dataset_dir / "deletion_requests.csv"

    @property
    def sample_deletion_requests_path(self) -> Path:
        return self.dataset_dir / "sample_deletion_requests.csv"

    @property
    def user_identities_path(self) -> Path:
        return self.dataset_dir / "user_identities.csv"

    @property
    def user_audit_log_path(self) -> Path:
        return self.dataset_dir / "user_audit_log.csv"

    @property
    def system_activity_path(self) -> Path:
        return self.dataset_dir / "system_activity.csv"

    @property
    def deletion_rules_path(self) -> Path:
        return self.dataset_dir / "deletion_rules.csv"

    @property
    def evidence_files_path(self) -> Path:
        return self.dataset_dir / "evidence_files.csv"

    @property
    def evidence_dir(self) -> Path:
        return self.dataset_dir / "evidence"


def get_settings(dataset_path_override: Optional[Path | str] = None) -> Settings:
    """Return Settings with optional dataset path override."""
    if dataset_path_override:
        return Settings(dataset_dir=Path(dataset_path_override))
    return Settings()
