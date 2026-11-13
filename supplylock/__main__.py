"""CLI. inspect already works; admit is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from supplylock.load import LoadError, load_index, load_json, load_lock


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="supplylock")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show lock packages and the install plan")
    ins.add_argument("--lock", required=True)
    ins.add_argument("--plan", required=True)
    ins.add_argument("--index", required=False)
    adm = sub.add_parser("admit", help="decide whether the plan is safe to install")
    adm.add_argument("--lock", required=True)
    adm.add_argument("--plan", required=True)
    adm.add_argument("--index", required=True)
    adm.add_argument("--policy", required=True)
    adm.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        lock = load_lock(args.lock)
        plan = load_json(args.plan)
    except (LoadError, OSError, KeyError) as exc:
        print(f"failed to load lock or plan: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps({
            "packages": {n: {"version": p.version, "source": p.source, "sha256": p.sha256, "scripts": p.scripts} for n, p in lock.items()},
            "plan": plan,
        }, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "admit":
        try:
            index = load_index(args.index)
            policy = load_json(args.policy)
        except (LoadError, OSError) as exc:
            print(f"failed to load index or policy: {exc}", file=sys.stderr)
            return 2
        from supplylock.engine import admit
        try:
            report = admit(lock, plan, index, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
