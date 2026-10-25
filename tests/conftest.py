"""Pytest configuration and shared fixtures for ghost_audit test suite."""

import sys
from pathlib import Path
import pytest

# Ensure 'code' directory is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def real_dataset_dir(repo_root: Path) -> Path:
    return repo_root / "dataset"
