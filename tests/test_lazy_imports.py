"""Tests for the lazy ``__getattr__`` import hooks on the package roots.

``PostgresTokenStorage`` is exposed lazily from both ``mcp_authflow`` and
``mcp_authflow.storage`` so that ``asyncpg`` is only imported when the Postgres
backend is actually requested.
"""

import pytest

import mcp_authflow
import mcp_authflow.storage
from mcp_authflow.storage.postgres import PostgresTokenStorage


def test_lazy_postgres_from_package_root() -> None:
    from mcp_authflow import PostgresTokenStorage as LazyRoot

    assert LazyRoot is PostgresTokenStorage


def test_lazy_postgres_from_storage_package() -> None:
    from mcp_authflow.storage import PostgresTokenStorage as LazyStorage

    assert LazyStorage is PostgresTokenStorage


def test_unknown_attribute_on_package_root_raises() -> None:
    missing = "DoesNotExist"
    with pytest.raises(AttributeError, match="no attribute 'DoesNotExist'"):
        getattr(mcp_authflow, missing)


def test_unknown_attribute_on_storage_package_raises() -> None:
    missing = "DoesNotExist"
    with pytest.raises(AttributeError, match="no attribute 'DoesNotExist'"):
        getattr(mcp_authflow.storage, missing)
