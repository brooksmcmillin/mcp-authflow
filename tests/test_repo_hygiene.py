"""Guards against committing generated coverage artifacts.

``.coverage`` and ``coverage.json`` are build outputs — CI regenerates them on
every run and uploads the JSON report as a workflow artifact. A copy committed
to the tree goes stale silently and then misleads coverage audits and reviewers,
so these tests fail if one ever lands in version control.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

ARTIFACT_NAMES = frozenset({"coverage.json", "coverage.xml"})
ARTIFACT_DIRS = frozenset({"htmlcov"})


def _tracked_paths() -> list[str]:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not running from a git checkout")
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def _is_coverage_artifact(path: str) -> bool:
    parts = Path(path).parts
    name = parts[-1]
    return (
        name in ARTIFACT_NAMES
        or name == ".coverage"
        or name.startswith(".coverage.")
        or bool(ARTIFACT_DIRS.intersection(parts))
    )


def test_no_coverage_artifacts_are_tracked() -> None:
    offenders = sorted(path for path in _tracked_paths() if _is_coverage_artifact(path))
    assert not offenders, (
        f"coverage artifacts are build outputs and must not be committed: {', '.join(offenders)}"
    )


def test_coverage_artifacts_are_gitignored() -> None:
    patterns = {
        stripped
        for line in (REPO_ROOT / ".gitignore").read_text().splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    }
    for pattern in (".coverage", ".coverage.*", "coverage.json", "coverage.xml", "htmlcov/"):
        assert pattern in patterns, f"{pattern} is missing from .gitignore"
