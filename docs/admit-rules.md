# Admit rules

Reuse `load_lock`, `load_index`, and `load_json`. The lock is the already-pinned tree. The plan is what the installer is about to fetch. The index is a snapshot of the private and public registries (this lab does not make network calls).

## Plan

`plan.packages` is a list of `{name, version, sha256, source}`. Every name in the plan must appear in the lock with the same version and lowercase sha256 (`lock_mismatch` otherwise, including a missing lock entry). A plan that omits a lock package is allowed only if that package is not reachable from `plan.roots` through lock dependencies (transitive). If a root or any transitive dependency is missing from the plan, that is `incomplete_plan`. Compute the transitive closure from `plan.roots` using *lock* dependency maps (dependency values are exact versions).

## Hash and source

The index has `public` and `private` maps of name -> list of `{version, sha256, unpublished?}`. Look up `(name, version)` in the registry named by the plan's `source`. Wrong hash is `hash_mismatch`. Unknown version is `unknown_version`. If `source` is `public` but the same name exists in the private index (any version), that is `dependency_confusion`, even when the hashes happen to match a public copy — the lab requires private names to be installed from `private`. If `source` is `private` and the name is not in the private index, `unknown_private`.

## Typosquat

`policy.protected_names` is a list of internal or popular names. For every *public* plan package whose name is not exactly one of those, compute a typo distance against each protected name: if the Levenshtein distance is 1, or the names differ only by hyphen/underscore/`/` vs `-` (after normalizing `_` and `-` to a common character), or one is the other plus a prefix/suffix in `policy.typo_affixes` (default `["js", "py", "lib", "-utils"]`), deny `typosquat` and name the protected name in `notes`. Private packages are not typo-checked (they already went through confusion).

## Scripts

If `policy.allow_scripts` is false, any non-empty `preinstall`, `install`, `postinstall`, or `prepare` script on a planned package (read from the *lock* record) is `blocked_script`. If scripts are allowed, still deny `blocked_script` when the script text (case-insensitive) contains any of: `curl `, `wget `, `invoke-webrequest`, `| sh`, `| bash`, `/etc/passwd`, `../` as a path fragment, or `child_process`. (A comment containing these strings still counts; this is a conservative lab rule.)

## Policy and report

Other policy fields: `allow_public` (if false, any public source is `public_denied`). `max_packages` limits the plan size (`too_many`).

Report: `decision`, `reason_codes` (stable order: `incomplete_plan`, `lock_mismatch`, `hash_mismatch`, `unknown_version`, `unknown_private`, `dependency_confusion`, `typosquat`, `blocked_script`, `public_denied`, `too_many`), `planned`, `notes`.

Exit 0 / 1 / 2 as usual.

## Public fixtures

`--lock fixtures/locks/app.lock.json --index fixtures/index.json --policy fixtures/policy.json --plan fixtures/plans/NAME.json`:

- `ok.json` → allow
- `hash-mismatch.json` → deny `hash_mismatch`
- `confused.json` → deny `dependency_confusion` (`internal-sdk` pulled from public)
- `typo.json` → deny `typosquat` (public `internel-sdk` vs protected `internal-sdk`)
- `postinstall.json` → deny `blocked_script`
- `incomplete.json` → deny `incomplete_plan`
- `lock-drift.json` → deny `lock_mismatch` (plan version is newer than the lock)
