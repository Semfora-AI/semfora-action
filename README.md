# Semfora Gate

Semantic PR gate for GitHub Actions: checks every pull request against your
team's policy in `semfora.toml` — protected domains, edits to load-bearing
code, new cross-module dependencies, complexity budgets — using graph
analysis no per-file linter can do.

**Nothing runs on your runner.** The action is a thin client: it queues the
gate run in Semfora's isolated analysis pipeline (the same one behind the
semfora.ai dashboard), which clones the PR via your Semfora GitHub App
connection, and polls for the verdict. No engine download, no checkout step,
no `fetch-depth` plumbing — and the report the runner receives contains
symbol names and numbers only, never source.

Requirements: a Semfora license key, and the repository must be connected on
[semfora.ai](https://semfora.ai) (the key must belong to the account that
owns the repo — a key can never gate someone else's code).

## Usage

```yaml
name: Semfora Gate
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  pull-requests: write   # report comment, inline findings, denial review

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: semfora-ai/semfora-action@v2
        with:
          semfora-key: ${{ secrets.SEMFORA_KEY }}
```

## What lands on the PR

With `pull-requests: write` granted, the gate projects its report onto the
PR itself:

- **Sticky report comment** — one comment per PR, edited in place on every
  run (pushes never pile up new comments; a red comment refreshes to green
  once the PR is fixed). It contains:
  - a **quality impact** table: the PR's measured cross-module coupling
    delta, its cognitive-complexity delta, and the repo's current **Vital
    Score** on the default branch for context;
  - the **domains the PR touches** as colored chips — each domain rendered
    in the *same deterministic color* semfora.ai assigns it on every
    dashboard page (the action ports the dashboard's golden-angle OKLCH
    registry and builds it from the canonical domain list the gate API
    vends), with the number of changed symbols per domain;
  - a findings table where every location **links to the exact line at the
    PR's head commit**;
  - two generated graphs when the data warrants them: a before/after
    **cognitive-complexity bar chart** for symbols that blew their budget,
    and a **module dependency graph** of cross-module edges the PR adds
    (Mermaid — GitHub renders all of it natively).

  Tune with `pr-comment: on-findings | always | never`.
- **One gate review** — the verdict and the line annotations land as a
  *single* review, the way a human reviewer's feedback does. Each policy
  finding is annotated on the exact line it hit, with the rule, severity,
  domains, and the measured numbers behind it (`cc=34 cc_before=12 …`) —
  deduplicated across runs; hits on lines outside the diff stay in the
  report table (still linked). When `semfora.toml` marks a domain protected
  at `severity = "error"` and the PR touches it, that review is submitted
  as **Changes Requested** with a one-line body naming the restricted
  domains, and dismissed automatically as soon as the gate passes or the
  failure is waived. Combined with a required status check this is a hard
  deny: the config in the repo decides, the action enforces. Tune with
  `line-comments: "false"` / `request-changes: "false"`.

**Bot identity:** when the gate response includes a Semfora posting token
(the default for repos connected via the Semfora GitHub App), everything
above posts as **`semfora[bot]`** with the Semfora avatar — the same
identity as the semfora.ai check runs. Without it, the action falls back to
the workflow token, which GitHub always renders as `github-actions[bot]`
(that name cannot be changed). The vended token also makes PR surfaces work
on fork PRs, where the workflow token is read-only.

## Required reviewers

The gate can route failing PRs to the humans who own the risk. List org
members or repo contributors (and org teams) in `required-reviewers`; when
the gate fails, the action requests them as reviewers on the PR. With
`require-approval: "true"`, the failure stays red until one of them approves
the PR **at its current head commit** — pushing new commits invalidates the
approval, and self-approval never counts. Mark the check as required in
branch protection and those people become de-facto required reviewers for
protected changes.

Set `require-approval: "admin"` to restrict the waiver further: only an
approval from someone with **admin permission on the repo** unblocks a
policy failure (usable with or without a `required-reviewers` list).

```yaml
name: Semfora Gate
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  pull_request_review:
    types: [submitted]          # re-run the gate when a reviewer approves

permissions:
  pull-requests: write          # comments, reviews, reviewer requests

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: semfora-ai/semfora-action@v2
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

## Require a reason for the change

With `require-reason: "true"` (off by default), a failing gate stays red
until someone **explains the change**: a PR comment mentioning `@semfora`
with the reason (10+ characters), from the **PR author or a repo
collaborator** — on fork PRs that means the outside contributor themselves
can unblock by explaining, no maintainer round-trip needed. Bots never
qualify, and a bare `@semfora` tag is not a reason.

The comment itself completes the loop:

1. The `issue_comment` trigger runs the workflow. Checks from comment runs
   attach to the *default branch*, not the PR — so this run never judges
   anything; it validates the comment and **re-runs the failed
   `pull_request` gate run** at the PR head (that's why it needs
   `actions: write`).
2. The re-run executes in PR context, finds the reason comment, and the
   required check turns green.
3. The accepted reason is **persisted to semfora.ai** for the repo, tied to
   the gate run and to what it justified: the restricted domains edited and
   the measured quality regression (coupling and complexity deltas) — so
   every waived denial has a durable, attributable "why".

```yaml
name: Semfora Gate
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  issue_comment:
    types: [created]            # "@semfora <reason>" re-runs the gate

permissions:
  pull-requests: write          # report comment, findings, reviews
  actions: write                # the comment run re-triggers the gate run

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: semfora-ai/semfora-action@v2
        with:
          semfora-key: ${{ secrets.SEMFORA_KEY }}
          require-reason: "true"
```

Combinable with `require-approval`: when both are set, a policy failure
needs the approval **and** the reason before it passes. Reasons are not
pinned to a commit — an explanation of intent survives follow-up pushes
(unlike approvals, which expire with the head commit).

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
| `semfora-key` | yes | — | License key; store as a secret. Verified (with repo entitlement) on every call. |
| `base` | no | PR base sha | Sha to gate against. |
| `poll-timeout-minutes` | no | `20` | How long to wait for the cloud run; raise for first-time indexes of very large repos. |
| `api-url` | no | `https://semfora.ai` | Self-hosted deployments only (must be https). |
| `pr-comment` | no | `on-findings` | Sticky PR comment with linked findings + graphs: `on-findings`, `always`, or `never`. Needs `pull-requests: write`. |
| `line-comments` | no | `true` | Inline review comments on the lines the rules hit. Needs `pull-requests: write`. |
| `request-changes` | no | `true` | Keep a Changes Requested review while policy denies the PR; auto-dismissed on pass/waive. |
| `required-reviewers` | no | — | Usernames / `org/team` slugs to request as reviewers. Needs `pull-requests: write`. |
| `request-reviewers-on` | no | `fail` | `fail`, `always`, or `never`. |
| `require-approval` | no | `false` | `"true"` → a required reviewer must approve the head commit to waive a failure; `"admin"` → the approver must be a repo admin. |
| `require-reason` | no | `false` | `"true"` → a failing gate stays red until a PR comment mentions `@semfora` with the reason (author or collaborator). Needs the `issue_comment` trigger + `actions: write`. The reason is recorded on semfora.ai. |
| `github-token` | no | workflow token | Only set to use a bot/app identity for the review requests. |

## Outputs

`verdict` (`pass`/`fail`, before any waiver), `errors`, `warnings`,
`waived` (`true` when every configured waiver — approval and/or reason —
was satisfied), `denied-domains` (comma-separated restricted domains hit
at error severity), `domains-touched` (comma-separated domains whose
symbols the PR changes, denied or not), `reason` (the accepted @semfora
change reason, single line), and `reason-author` (who gave it).

## Exit behavior

- Policy errors → the step fails (blocks the PR when the check is required),
  unless waived by a required reviewer's approval (see above).
- Warnings → annotations + summary only; the step passes.
- Analysis problems → the step fails with an `::error` explaining why —
  distinct from a policy failure.

## Security

- **Nothing executes on your runner and no source passes through it.**
  Analysis happens in Semfora's ephemeral, isolated pipeline containers —
  cloned via your GitHub App installation, deleted when the run ends (the
  same source-protection contract as the semfora.ai dashboard). The gate
  report the action receives is symbol names and numbers only.
- **A key only gates its own repos.** Every API call verifies the license
  key AND that the key's billing account owns the repository — invalid
  keys, revoked keys, and other tenants' repos all get the same uniform
  rejection.
- The license key is only ever sent over https to `api-url` (POST bodies,
  never URLs) and is masked in logs. Store it as a repository or
  organization secret.
- The action is dependency-free — no `node_modules`, no supply chain. One
  auditable runtime file (`index.js`; `test.js` is dev-only and never runs
  in your workflow).
