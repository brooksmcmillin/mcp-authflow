"""Keeps the README in sync with the code and the documentation site.

The README "Features" list and the docs "What's in the box" list are both
hand-maintained, so a feature shipped with a docs entry and no README bullet
goes unnoticed — that is exactly how RFC 7591 Dynamic Client Registration
stayed missing from the README for five releases. These tests fail if the two
lists ever drift apart on the RFCs they advertise.

The README also documents the `TokenStorage` interface as a table, which
subclassers read as the interface spec; a test here fails if a new abstract
method lands without a row.

Finally, the README annotates every `mcp_authflow.responses` helper with the
HTTP status it returns, and each helper's docstring summary repeats it (that
summary renders into `docs/api/responses.md` via mkdocstrings). Both are prose,
so they drifted: `slow_down()` was advertised as "400 or 429" while the code
only ever returned 400. Tests here call each fixed-status helper and fail if
either the README annotation or the docstring summary names a status the helper
cannot produce.
"""

import inspect
import re
from collections.abc import Iterator
from pathlib import Path

from starlette.responses import JSONResponse

from mcp_authflow import responses
from mcp_authflow.storage.base import TokenStorage

REPO_ROOT = Path(__file__).resolve().parent.parent

RFC_PATTERN = re.compile(r"RFC (\d{4})")


def _bullets_under(markdown: str, heading: str) -> list[str]:
    lines = markdown.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    bullets = []
    for line in lines[start + 1 :]:
        if line.startswith("#"):
            break
        if line.startswith("- "):
            bullets.append(line)
    return bullets


def _readme_features() -> list[str]:
    readme = (REPO_ROOT / "README.md").read_text()
    return _bullets_under(readme, "## Features")


def _docs_features() -> list[str]:
    index = (REPO_ROOT / "docs" / "index.md").read_text()
    return _bullets_under(index, "## What's in the box")


def test_readme_advertises_every_rfc_the_docs_advertise() -> None:
    readme_rfcs = set(RFC_PATTERN.findall("\n".join(_readme_features())))
    docs_rfcs = set(RFC_PATTERN.findall("\n".join(_docs_features())))
    missing = sorted(docs_rfcs - readme_rfcs)
    assert not missing, (
        "the README Features list omits RFCs the docs advertise: "
        f"{', '.join('RFC ' + rfc for rfc in missing)}"
    )


def test_readme_features_mention_dynamic_client_registration() -> None:
    features = "\n".join(_readme_features())
    assert "7591" in features
    assert "Dynamic Client Registration" in features


def _readme_storage_table_methods() -> set[str]:
    readme = (REPO_ROOT / "README.md").read_text()
    lines = readme.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("**Storage interface:**"))
    methods = set()
    for line in lines[start + 1 :]:
        if methods and not line.startswith("|"):
            break
        match = re.match(r"\|\s*`(\w+)\(", line)
        if match:
            methods.add(match.group(1))
    return methods


def test_readme_storage_table_documents_every_abstract_method() -> None:
    abstract = set(TokenStorage.__abstractmethods__)
    missing = sorted(abstract - _readme_storage_table_methods())
    assert not missing, (
        "the README storage-interface table omits abstract TokenStorage methods: "
        f"{', '.join(missing)}"
    )


STATUS_PATTERN = re.compile(r"\b([1-5]\d\d)\b")


def _readme_response_annotations() -> dict[str, str]:
    """Map each helper in the README's responses import block to its comment."""
    readme = (REPO_ROOT / "README.md").read_text()
    lines = readme.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.startswith("from mcp_authflow.responses import (")
    )
    annotations = {}
    for line in lines[start + 1 :]:
        if line.startswith(")"):
            break
        match = re.match(r"\s*(\w+),\s*#\s*(.+)$", line)
        if match:
            annotations[match.group(1)] = match.group(2)
    return annotations


def _fixed_status_helpers() -> Iterator[tuple[str, str, JSONResponse]]:
    """Yield (name, README annotation, response) for helpers with a fixed status.

    Helpers that take a ``status_code`` argument (``oauth_error``,
    ``server_error``, ``backend_oauth_error``) legitimately return more than one
    status, so their annotations are not checked.
    """
    for name, annotation in _readme_response_annotations().items():
        func = getattr(responses, name)
        params = inspect.signature(func).parameters
        if "status_code" in params:
            continue
        required = [p for p in params.values() if p.default is p.empty]
        assert all(p.annotation is str for p in required), name
        yield name, annotation, func(*["docs consistency check"] * len(required))


def test_readme_annotations_match_helper_status_codes() -> None:
    for name, annotation, response in _fixed_status_helpers():
        documented = {int(code) for code in STATUS_PATTERN.findall(annotation)}
        assert documented == {response.status_code}, (
            f"the README annotates {name}() with {sorted(documented)} "
            f"but it returns {response.status_code}"
        )


def test_docstring_summaries_match_helper_status_codes() -> None:
    for name, _annotation, response in _fixed_status_helpers():
        summary = (getattr(responses, name).__doc__ or "").splitlines()[0]
        documented = {int(code) for code in STATUS_PATTERN.findall(summary)}
        assert documented == {response.status_code}, (
            f"the {name}() docstring summary names {sorted(documented)} "
            f"but it returns {response.status_code}"
        )
