"""Install plan admission. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from supplylock.load import Package


def admit(
    lock: dict[str, Package],
    plan: dict[str, Any],
    index: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    raise NotImplementedError("admit is not implemented in this snapshot")
