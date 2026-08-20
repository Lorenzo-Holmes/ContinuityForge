"""ContinuityForge: provenance-aware, timeline-safe persona memory compiler."""

from __future__ import annotations

__version__ = "0.3.0a3"

# Imports are deliberately small so ``import continuityforge`` never opens a
# database and remains safe for tooling that only needs version metadata.

__all__ = ["__version__"]
