"""Tests for the inspect CLI command and cross-directory execution."""

import json
import os
import subprocess
import sys
from pathlib import Path

from ghost_audit.cli import main as cli_main
from ghost_audit.config import EXPECTED_COUNTS, Settings, get_settings


def test_cli_inspect_real_dataset_text(capsys, real_dataset_dir: Path):
    ret = cli_main(["inspect", "--dataset", str(real_dataset_dir)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Overall Status    : VALID" in captured.out
    assert "Requests           :   518 /   518 [MATCH]" in captured.out
    assert "User Identities    :   850 /   850 [MATCH]" in captured.out
    assert "Evidence Files     :    94 /    94 [MATCH]" in captured.out


def test_cli_inspect_real_dataset_sample(capsys, real_dataset_dir: Path):
    ret = cli_main(["inspect", "--sample", "--dataset", str(real_dataset_dir)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Mode              : SAMPLE" in captured.out
    assert "Requests           :    32 /    32 [MATCH]" in captured.out


def test_cli_inspect_json_format(capsys, real_dataset_dir: Path):
    ret = cli_main(["inspect", "--json", "--dataset", str(real_dataset_dir)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "VALID"
    assert data["counts"]["selected_requests"] == 518
    assert data["counts"]["identities"] == 850
    assert data["counts"]["historical_changes"] == 306
    assert data["counts"]["activity_events"] == 4011
    assert data["counts"]["policy_rules"] == 15
    assert data["counts"]["evidence_files"] == 94
    assert data["counts_match_expected"]["selected_requests"] is True
    assert data["evidence_format_breakdown"] == {
        ".json": 28,
        ".log": 26,
        ".pdf": 4,
        ".png": 11,
        ".sql": 24,
        ".txt": 1,
    }


def test_cli_inspect_invalid_dataset_fails(tmp_path: Path):
    # Empty directory with missing files
    empty_dataset = tmp_path / "empty_dataset"
    empty_dataset.mkdir()
    ret = cli_main(["inspect", "--dataset", str(empty_dataset)])
    assert ret == 1


def test_cli_execution_from_different_working_directory(tmp_path: Path, repo_root: Path):
    # Run python code/main.py inspect from a completely different working directory (tmp_path)
    main_py = repo_root / "code" / "main.py"
    proc = subprocess.run(
        [sys.executable, str(main_py), "inspect", "--json"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["status"] == "VALID"
    assert data["counts"]["selected_requests"] == 518
