"""Public constants that form part of the compatibility contract."""

from __future__ import annotations

SCHEMA_VERSION = 2
PACKAGE_SCHEMA = "continuityforge.memory-pack/v0.2"
V01_PACKAGE_SCHEMA = "continuityforge.memory-pack/v0.1"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_VALIDATION_FAILED = 3
EXIT_GOVERNANCE_FAILED = 4
EXIT_LEDGER_FAILED = 5

SUPPORTED_SOURCE_SUFFIXES = frozenset(
    {".txt", ".md", ".markdown", ".json", ".srt"}
)

