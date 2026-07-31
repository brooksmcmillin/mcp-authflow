"""Keeps the README in sync with the code and the documentation site.

The README "Features" list and the docs "What's in the box" list are both
hand-maintained, so a feature shipped with a docs entry and no README bullet
goes unnoticed — that is exactly how RFC 7591 Dynamic Client Registration
stayed missing from the README for five releases. These tests fail if the two
lists ever drift apart on the RFCs they advertise.

The README also documents the `TokenStorage` interface as a table, which
subclassers read as the interface spec; a test here fails if a new abstract
method lands without a row.
"""

import re
from pathlib import Path

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
