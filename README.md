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

permissions:
  contents: read

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

## Required reviewers

The gate can route failing PRs to the humans who own the risk. List org
members or repo contributors (and org teams) in `required-reviewers`; when
the gate fails, the action requests them as reviewers on the PR. With
`require-approval: "true"`, the failure stays red until one of them approves
the PR **at its current head commit** — pushing new commits invalidates the
approval. Mark the check as required in branch protection and those people
become de-facto required reviewers for protected changes.

```yaml
name: Semfora Gate
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  pull_request_review:
    types: [submitted]          # re-run the gate when a reviewer approves

permissions:
  contents: read
  pull-requests: write          # needed to request reviewers

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: semfora-ai/semfora-action@v1
        with:
          semfora-key: ${{ secrets.SEMFORA_KEY }}
          required-reviewers: alice, bob, my-org/platform-team
          require-approval: "true"
```

Notes:

- Every username is validated before the request: GitHub only accepts
  reviewers who have access to the repo, so entries that are not
  collaborators (this covers org members with repo access *and* outside
  contributors) are skipped with a warning explaining why.
- The PR author is never requested, and people who already reviewed or are
  already requested are not re-pinged.
- Fork PRs get a read-only `GITHUB_TOKEN`, so reviewer requests are skipped
  there with a warning; the gate verdict itself is unaffected.
- Reviewer plumbing can never flip a passing gate to failing — any error in
  it degrades to a warning.

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
| `api-url` | no | `https://semfora.ai` | Self-hosted deployments only (must be https). |
| `required-reviewers` | no | — | Usernames / `org/team` slugs to request as reviewers. Needs `pull-requests: write`. |
| `request-reviewers-on` | no | `fail` | `fail`, `always`, or `never`. |
| `require-approval` | no | `false` | `"true"` → a policy failure passes only after a required reviewer approves the head commit. |
| `github-token` | no | workflow token | Only set to use a bot/app identity for the review requests. |

## Outputs

`verdict` (`pass`/`fail`, before any waiver), `errors`, `warnings`,
`waived` (`true` when an approval waived a policy failure).

## Exit behavior

- Policy errors → the step fails (blocks the PR when the check is required),
  unless waived by a required reviewer's approval (see above).
- Warnings → annotations + summary only; the step passes.
- Analysis problems → the step fails with an `::error` explaining why —
  distinct from a policy failure.

## Security

- **Your code never leaves the runner.** The engine analyzes locally; the
  only outbound calls are license verification, the (optional) engine
  download, and the GitHub API for reviewer requests.
- The license key is only ever sent over https to `api-url` and is masked
  in logs. Store it as a repository or organization secret.
- Downloaded engine binaries are refused unless the verification response
  includes a sha256 checksum, and the checksum is enforced before the
  binary is ever executed. Air-gapped runners can pin `engine-path`
  instead.
- The action is dependency-free — no `node_modules`, no supply chain. One
  auditable file.
