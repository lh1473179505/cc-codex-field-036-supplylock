"""Load a lockfile, a desired install plan, and a registry index. Policy checks are not implemented here."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class LoadError(Exception):
    pass


@dataclass
class Package:
    name: str
    version: str
    sha256: str
    source: str  # "private" | "public"
    scripts: dict[str, str]
    dependencies: dict[str, str]


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(str(exc)) from exc


def load_lock(path: str | Path) -> dict[str, Package]:
    raw = load_json(path)
    out: dict[str, Package] = {}
    for item in raw.get("packages") or []:
        pkg = Package(
            name=str(item["name"]),
            version=str(item["version"]),
            sha256=str(item["sha256"]).lower(),
            source=str(item.get("source", "public")),
            scripts=dict(item.get("scripts") or {}),
            dependencies={str(k): str(v) for k, v in (item.get("dependencies") or {}).items()},
        )
        out[pkg.name] = pkg
    return out


def load_index(path: str | Path) -> dict[str, Any]:
    return load_json(path)
