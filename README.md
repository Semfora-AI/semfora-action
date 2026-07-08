# Semfora Gate

Semantic PR gate for GitHub Actions: checks every pull request against your
team's policy in `semfora.toml` — protected domains, edits to load-bearing
code, new cross-module dependencies, complexity budgets — using graph
analysis no per-file linter can do.

**Your code never leaves your runner.** The engine analyzes locally; the only
network calls are the license verification and (optionally) fetching the
engine binary. Requires a Semfora license key — get one at
[semfora.ai](https://semfora.ai).

## Usage

```yaml
name: Semfora Gate
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # the gate diffs against the PR base commit
      - uses: semfora-ai/semfora-action@v1
        with:
          semfora-key: ${{ secrets.SEMFORA_KEY }}
```

## Policy lives in your repo

The same `semfora.toml` drives this action, the semfora.ai cloud gate, and
every developer's local `semfora-engine ci` — one policy, three surfaces:

```toml
[groups.payment]
description = "Payment processing and reconciliation"
modules = ["src.billing", "src.payments"]

[gate.protected]
severity = "error"
groups = ["payment"]

[gate.load_bearing]
severity = "warn"
threshold = 60

[gate.load_bearing.groups.payment]   # stricter for the payment domain
severity = "error"
threshold = 40
```

## Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `semfora-key` | yes | — | License key; store as a secret. Verified before every run. |
| `base` | no | PR base sha | Ref/sha to gate against. |
| `target-ref` | no | `HEAD` | `WORKING` gates uncommitted changes. |
| `engine-path` | no | — | Pre-provisioned binary for air-gapped/self-hosted runners (key still verified). |
| `api-url` | no | `https://semfora.ai` | Self-hosted deployments only. |

## Outputs

`verdict` (`pass`/`fail`), `errors`, `warnings`.

## Exit behavior

- Policy errors → the step fails (blocks the PR when the check is required).
- Warnings → annotations + summary only; the step passes.
- Analysis problems → the step fails with an `::error` explaining why —
  distinct from a policy failure.
