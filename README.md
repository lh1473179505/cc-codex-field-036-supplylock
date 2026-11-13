# supplylock

An install-plan admission tool: lockfile hash pins, private-vs-public confusion, typo-squatting, and install-script review.

`python -m supplylock inspect --lock fixtures/locks/app.lock.json --plan fixtures/plans/ok.json` already shows the tree. `admit` is still a stub.

Standard library only. No Docker, no npm/pip network calls.
