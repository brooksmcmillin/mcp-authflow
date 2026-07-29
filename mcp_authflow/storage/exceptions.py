"""Exceptions raised by the token storage backends.

Every error defined here reports a *deployment or programming* fault: a missing
setting, a token table that never gained a column the library needs, a method
called before ``initialize()``. None of them is transient, and none of them is
fixed by retrying. That matters because the other failures a storage backend
can hit -- an unreachable database, a dropped connection, a saturated pool --
surface as driver errors (``asyncpg.PostgresError``) or ``OSError``, and *are*
often transient.

Servers commonly want to treat those two groups differently: degrade or retry
when the database blips, but refuse to start when the store is misconfigured,
since starting anyway means serving traffic with tokens that silently do not
persist. Before this taxonomy existed both groups arrived as bare
``RuntimeError`` / ``ValueError``, so telling them apart meant matching on the
message text. Now the distinction is expressible directly::

    try:
        await storage.initialize()
    except StorageError:
        # Misconfigured: the operator asked for persistence and cannot have it.
        raise
    except (asyncpg.PostgresError, OSError):
        logger.warning("Database unavailable, retrying...")

Each class also inherits from the builtin that the corresponding failure raised
before this module existed, so callers already catching ``RuntimeError`` or
``ValueError`` keep working unchanged.
"""

__all__ = [
    "SchemaDriftError",
    "StorageConfigError",
    "StorageError",
    "StorageNotInitializedError",
]


class StorageError(Exception):
    """Base class for token-storage faults that retrying cannot fix.

    Catch this to handle every misconfiguration the storage backends report, as
    distinct from the driver-level errors a transient database problem raises.
    """


class StorageConfigError(StorageError, ValueError):
    """The storage backend is missing configuration it requires.

    Raised by :meth:`PostgresTokenStorage.initialize` when no database URL was
    passed to the constructor and ``DATABASE_URL`` is unset.

    Also inherits from :class:`ValueError`, which this condition raised before
    the taxonomy existed.
    """


class SchemaDriftError(StorageError, RuntimeError):
    """An existing token table is missing a column the library requires.

    ``CREATE TABLE IF NOT EXISTS`` is a no-op on a table that already exists, so
    re-running the documented DDL after an upgrade never adds a column a newer
    release introduced. :meth:`PostgresTokenStorage.initialize` detects that at
    startup and raises this instead of letting the drift surface later as a
    mid-request ``UndefinedColumnError``. The message names the offending tables
    and columns; the fix is the ``ALTER TABLE`` recipe in the README's "Schema
    versioning and upgrades" section.

    Also inherits from :class:`RuntimeError`, which this condition raised before
    the taxonomy existed.
    """


class StorageNotInitializedError(StorageError, RuntimeError):
    """A storage method was called before ``initialize()``.

    A lifecycle bug in the calling code rather than a deployment fault: the
    backend has no connection pool (Postgres) or no initialized token maps
    (memory) to work with yet.

    Also inherits from :class:`RuntimeError`, which this condition raised before
    the taxonomy existed.
    """
