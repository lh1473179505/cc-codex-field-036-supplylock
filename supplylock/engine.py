"""Install plan admission; see docs/admit-rules.md."""

from __future__ import annotations

from typing import Any

from supplylock.load import Package


REASON_ORDER = [
    "incomplete_plan",
    "lock_mismatch",
    "hash_mismatch",
    "unknown_version",
    "unknown_private",
    "dependency_confusion",
    "typosquat",
    "blocked_script",
    "public_denied",
    "too_many",
]

SCRIPT_KEYS = ("preinstall", "install", "postinstall", "prepare")
FORBIDDEN_SCRIPT_PATTERNS = (
    "curl ",
    "wget ",
    "invoke-webrequest",
    "| sh",
    "| bash",
    "/etc/passwd",
    "../",
    "child_process",
)
DEFAULT_AFFIXES = ["js", "py", "lib", "-utils"]


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, start=1):
        current = [i]
        for j, char_right in enumerate(right, start=1):
            substitution_cost = 0 if char_left == char_right else 1
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + substitution_cost,
            ))
        previous = current
    return previous[-1]


def _normalize_separators(name: str) -> str:
    return name.replace("_", "-").replace("/", "-")


def _is_typosquat(name: str, protected: str, affixes: list[str]) -> bool:
    if _levenshtein(name, protected) == 1:
        return True
    if name != protected and _normalize_separators(name) == _normalize_separators(protected):
        return True
    for affix in affixes:
        if name == protected + affix or name == affix + protected:
            return True
        if protected == name + affix or protected == affix + name:
            return True
    return False


def admit(
    lock: dict[str, Package],
    plan: dict[str, Any],
    index: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    notes: list[str] = []
    reason_codes: set[str] = set()

    def deny(code: str, note: str) -> None:
        reason_codes.add(code)
        notes.append(note)

    plan_packages = list(plan.get("packages") or [])
    roots = [str(root) for root in plan.get("roots") or []]
    protected_names = [str(name) for name in policy.get("protected_names") or []]
    affixes = list(policy.get("typo_affixes") or DEFAULT_AFFIXES)
    allow_scripts = bool(policy.get("allow_scripts", False))
    allow_public = bool(policy.get("allow_public", True))
    max_packages = policy.get("max_packages")

    private_index = index.get("private") or {}
    public_index = index.get("public") or {}

    planned = [
        (
            str(item.get("name", "")),
            str(item.get("version", "")),
            str(item.get("sha256", "")).lower(),
            str(item.get("source", "public")),
        )
        for item in plan_packages
    ]

    if max_packages is not None and len(planned) > int(max_packages):
        deny("too_many", f"too_many: plan has {len(planned)} packages, policy max is {max_packages}")

    plan_names = {name for name, _version, _sha, _source in planned}

    required: set[str] = set()
    stack = list(roots)
    while stack:
        current = stack.pop()
        if current in required:
            continue
        required.add(current)
        locked = lock.get(current)
        if locked is not None:
            stack.extend(locked.dependencies.keys())
    for missing in sorted(required - plan_names):
        deny("incomplete_plan", f"incomplete_plan: {missing} is reachable from plan.roots but missing from the plan")

    for name, version, sha, source in planned:
        locked = lock.get(name)
        if locked is None:
            deny("lock_mismatch", f"lock_mismatch: {name} has no entry in the lockfile")
        elif locked.version != version:
            deny(
                "lock_mismatch",
                f"lock_mismatch: {name} plan version {version} differs from lock version {locked.version}",
            )

        registry: dict[str, Any] | None
        if source == "public":
            if not allow_public:
                deny("public_denied", f"public_denied: {name} would be installed from the public registry")
            if name in private_index:
                deny(
                    "dependency_confusion",
                    f"dependency_confusion: {name} exists in the private index but the plan uses the public registry",
                )
            registry = public_index
        elif source == "private":
            if name not in private_index:
                deny("unknown_private", f"unknown_private: {name} is absent from the private index")
                registry = None
            else:
                registry = private_index
        else:
            registry = index.get(source) or {}

        if registry is not None:
            entries = registry.get(name) or []
            entry = next((candidate for candidate in entries if str(candidate.get("version")) == version), None)
            if entry is None:
                deny("unknown_version", f"unknown_version: {source} registry has no {name}@{version}")
            elif str(entry.get("sha256", "")).lower() != sha:
                deny("hash_mismatch", f"hash_mismatch: {name}@{version} sha256 does not match the {source} registry")

        if source == "public":
            for protected in protected_names:
                if name == protected:
                    continue
                if _is_typosquat(name, protected, affixes):
                    deny(
                        "typosquat",
                        f"typosquat: public package {name} resembles protected name {protected}",
                    )
                    break

        if locked is not None:
            for script_key in SCRIPT_KEYS:
                script = locked.scripts.get(script_key)
                if not script:
                    continue
                if not allow_scripts:
                    deny(
                        "blocked_script",
                        f"blocked_script: {name} has a {script_key} script but allow_scripts is false",
                    )
                    break
                lowered = script.lower()
                if any(pattern in lowered for pattern in FORBIDDEN_SCRIPT_PATTERNS):
                    deny(
                        "blocked_script",
                        f"blocked_script: {name} {script_key} script contains a forbidden pattern",
                    )
                    break

    ordered_codes = [code for code in REASON_ORDER if code in reason_codes]
    return {
        "decision": "allow" if not ordered_codes else "deny",
        "reason_codes": ordered_codes,
        "planned": len(planned),
        "notes": notes,
    }
