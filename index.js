// ---------------------------------------------------------------------------
// Semfora Gate — GitHub Action entry point (SEM-226).
//
// Deliberately dependency-free (no @actions/* toolkit): everything below is
// plain Node 20 against the documented Actions contracts (INPUT_* env,
// workflow commands on stdout, GITHUB_OUTPUT / GITHUB_STEP_SUMMARY files).
// A security-tool action should be auditable in one file.
//
// Flow:
//   1. Verify the license key against semfora.ai — no key, no gate. This is
//      the "approved customers only" control; the response also tells us
//      which engine build to fetch.
//   2. Resolve the engine binary: customer-provided path (air-gapped) or
//      verified download cached in the tool cache. Downloads are refused
//      without a checksum.
//   3. Run `semfora-engine ci` on the PR diff. The engine runs entirely on
//      this runner — source code never leaves it. Exit 20 = policy fail
//      (mirrors the cloud pipeline); anything else nonzero = analysis error.
//   4. Project the report: step summary (markdown), inline annotations
//      (::error/::warning file=), and action outputs.
//   5. PR surfaces (optional, all degrade to warnings — they can never flip
//      the gate verdict):
//      - sticky comment with linked findings, a complexity chart, and a
//        cross-module dependency graph (Mermaid — GitHub renders it);
//      - inline review comments on the exact lines the rules hit;
//      - a Changes Requested review when policy denies the PR (restricted
//        domains in semfora.toml), dismissed automatically once the gate
//        passes or is waived;
//      - required reviewers: request the configured org members /
//        contributors, and let an approval of the current head commit waive
//        a policy failure. require-approval: "admin" restricts the waiver
//        to repo admins.
// ---------------------------------------------------------------------------

const { execFileSync, execFile } = require("node:child_process")
const { createHash } = require("node:crypto")
const fs = require("node:fs")
const path = require("node:path")

// --- tiny Actions runtime helpers --------------------------------------------

function input(name) {
  const v = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`]
  return v === undefined ? "" : v.trim()
}

/** Escape data for a workflow command value. */
function esc(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A")
}
/** Escape a workflow command property (also , and :). */
function escProp(s) {
  return esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C")
}

function annotate(level, { file, line, title, message }) {
  const props = file
    ? `file=${escProp(file)},line=${line},title=${escProp(title)}`
    : `title=${escProp(title)}`
  console.log(`::${level} ${props}::${esc(message)}`)
}

function notice(message) {
  console.log(`::notice::${esc(message)}`)
}

function warn(message) {
  console.log(`::warning::${esc(message)}`)
}

/** Register a secret with the runner's log scrubber. */
function mask(secret) {
  if (secret) console.log(`::add-mask::${secret}`)
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`)
  }
}

function appendSummary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`)
  }
}

function fail(message) {
  console.log(`::error::${esc(message)}`)
  process.exit(1)
}

/**
 * fetch with a per-attempt timeout, retrying network errors and 5xx.
 * 4xx responses are returned as-is (they are answers, not transport faults).
 */
async function fetchWithRetry(url, init, { attempts = 3, timeoutMs = 30_000 } = {}) {
  let lastErr
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) })
      if (res.status < 500 || attempt === attempts) return res
      lastErr = new Error(`HTTP ${res.status}`)
    } catch (e) {
      if (attempt === attempts) throw e
      lastErr = e
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt))
  }
  throw lastErr
}

function requireHttps(rawUrl, what) {
  let u
  try {
    u = new URL(rawUrl)
  } catch {
    fail(`${what} is not a valid URL: ${rawUrl}`)
  }
  const isLoopback = u.hostname === "localhost" || u.hostname === "127.0.0.1"
  if (u.protocol !== "https:" && !isLoopback) {
    fail(`${what} must be https (got ${u.protocol}//). Refusing to send the license key or fetch a binary over plaintext.`)
  }
}

// --- 1. license verification --------------------------------------------------

async function verifyKey(apiUrl, key) {
  let res
  try {
    res = await fetchWithRetry(`${apiUrl.replace(/\/$/, "")}/api/action/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key, platform: "linux-x64" }),
    })
  } catch (e) {
    fail(
      `Could not reach Semfora to verify the license key (${e.message}). ` +
        "Air-gapped runners must set engine-path AND have network access to " +
        "the api-url; fully offline licensing is coming.",
    )
  }
  if (res.status === 403) {
    fail(
      "Semfora license key was rejected. Gate runs are available to " +
        "licensed customers — get or renew a key at https://semfora.ai.",
    )
  }
  if (!res.ok) fail(`Semfora verification failed (${res.status}).`)
  return res.json()
}

// --- 2. engine resolution ------------------------------------------------------

async function resolveEngine(verified) {
  const provided = input("engine-path")
  if (provided) {
    if (!fs.existsSync(provided)) fail(`engine-path does not exist: ${provided}`)
    return provided
  }
  if (!verified.downloadUrl) {
    fail(
      "No engine download is available for this platform yet. Provision " +
        "the binary yourself and pass it via the engine-path input.",
    )
  }
  requireHttps(verified.downloadUrl, "The engine download URL")
  if (!verified.sha256) {
    fail(
      "Semfora did not provide a checksum for the engine download — " +
        "refusing to run an unverified binary. Pass a pre-provisioned " +
        "binary via engine-path, or contact support@semfora.ai.",
    )
  }
  const cacheRoot = process.env.RUNNER_TOOL_CACHE || fs.mkdtempSync("/tmp/semfora-")
  const dir = path.join(cacheRoot, "semfora-engine", verified.engineVersion)
  const bin = path.join(dir, "semfora-engine")
  if (!fs.existsSync(bin)) {
    fs.mkdirSync(dir, { recursive: true })
    const res = await fetchWithRetry(verified.downloadUrl, {}, {
      attempts: 2,
      timeoutMs: 5 * 60 * 1000,
    })
    if (!res.ok) fail(`Engine download failed (${res.status}).`)
    const bytes = Buffer.from(await res.arrayBuffer())
    const digest = createHash("sha256").update(bytes).digest("hex")
    if (digest !== verified.sha256) {
      fail("Engine binary checksum mismatch — refusing to run it.")
    }
    // Atomic publish: concurrent jobs on a self-hosted runner share the tool
    // cache, and a half-written binary must never be executable.
    const tmp = `${bin}.${process.pid}.tmp`
    fs.writeFileSync(tmp, bytes, { mode: 0o755 })
    fs.renameSync(tmp, bin)
  }
  return bin
}

// --- GitHub context ------------------------------------------------------------

function readEvent() {
  const eventPath = process.env.GITHUB_EVENT_PATH
  if (!eventPath || !fs.existsSync(eventPath)) return {}
  try {
    return JSON.parse(fs.readFileSync(eventPath, "utf8"))
  } catch {
    return {}
  }
}

const GITHUB_API = (process.env.GITHUB_API_URL || "https://api.github.com").replace(/\/$/, "")

async function gh(token, method, pathname, body) {
  return fetchWithRetry(
    `${GITHUB_API}${pathname}`,
    {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "semfora-action",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    },
    { attempts: 2 },
  )
}

async function ghPaged(token, pathname, { maxPages = 10 } = {}) {
  const sep = pathname.includes("?") ? "&" : "?"
  const items = []
  for (let page = 1; page <= maxPages; page++) {
    const res = await gh(token, "GET", `${pathname}${sep}per_page=100&page=${page}`)
    if (!res.ok) break
    const batch = await res.json()
    items.push(...batch)
    if (batch.length < 100) break
  }
  return items
}

// --- report rendering (sticky comment, graphs, links) ---------------------------

const COMMENT_MARKER = "<!-- semfora-gate-comment -->"
const LINE_MARKER = "<!-- semfora-gate-line -->"
const REVIEW_MARKER = "<!-- semfora-gate-review -->"

function codeLink(repo, sha, file, line) {
  const server = (process.env.GITHUB_SERVER_URL || "https://github.com").replace(/\/$/, "")
  return `${server}/${repo}/blob/${sha}/${file}#L${line}`
}

/** Mermaid node ids must be plain; labels carry the real name. */
function mermaidId(name) {
  return `n_${String(name).replace(/[^A-Za-z0-9_]/g, "_")}`
}
function mermaidStr(s) {
  return `"${String(s).replace(/"/g, "'")}"`
}

/** Restricted domains behind error-severity `protected` hits. */
function deniedDomains(report) {
  const domains = new Set()
  for (const h of report.rule_hits ?? []) {
    if (h.rule === "protected" && h.severity === "error") {
      for (const g of h.groups ?? []) domains.add(g)
    }
  }
  return [...domains].sort()
}

function formatEvidence(evidence) {
  return Object.entries(evidence ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(", ")
}

function findingsTable(report, repo, headSha) {
  const hits = (report.rule_hits ?? []).slice(0, 30)
  if (hits.length === 0) return ""
  const rows = hits.map((h) => {
    const location =
      h.file && headSha
        ? `[\`${h.file}:${h.line}\`](${codeLink(repo, headSha, h.file, h.line)})`
        : h.file
          ? `\`${h.file}:${h.line}\``
          : h.module || ""
    const severity = h.severity === "error" ? "🛑" : "⚠️"
    const evidence = formatEvidence(h.evidence)
    const detail = `${h.message}${evidence ? ` (${evidence})` : ""}`
    return `| ${severity} | ${h.rule} | ${location} | ${h.symbol ? `\`${h.symbol}\`` : "—"} | ${detail.replace(/\|/g, "\\|")} |`
  })
  const more =
    (report.rule_hits_total ?? hits.length) > hits.length
      ? `\n_…and ${report.rule_hits_total - hits.length} more — see the workflow step summary._`
      : ""
  return [
    "#### Findings",
    "",
    "| | Rule | Location | Symbol | Detail |",
    "|---|---|---|---|---|",
    ...rows,
    more,
    "",
  ].join("\n")
}

/** Before/after cognitive-complexity bar chart for complexity-rule hits. */
function complexityChart(report) {
  const hits = (report.rule_hits ?? [])
    .filter((h) => h.rule === "complexity" && h.evidence?.cc !== undefined)
    .slice(0, 12)
  if (hits.length === 0) return ""
  const names = hits.map((h) => mermaidStr(h.symbol || h.module || "?"))
  const after = hits.map((h) => h.evidence.cc)
  const before = hits.map((h) => h.evidence.cc_before ?? 0)
  return [
    "#### Complexity increase",
    "",
    "```mermaid",
    "xychart-beta",
    `  title ${mermaidStr("Cognitive complexity (tall bar = this PR, overlay = before)")}`,
    `  x-axis [${names.join(", ")}]`,
    `  y-axis ${mermaidStr("cognitive complexity")}`,
    `  bar [${after.join(", ")}]`,
    `  bar [${before.join(", ")}]`,
    "```",
    "",
  ].join("\n")
}

/** Module dependency graph of coupling the PR adds. */
function couplingGraph(report) {
  const pairs = (report.coupling_delta?.pairs ?? [])
    .filter((p) => (p.after ?? 0) > (p.before ?? 0))
    .slice(0, 20)
  if (pairs.length === 0) return ""
  const lines = ["```mermaid", "graph LR"]
  for (const p of pairs) {
    const label =
      (p.before ?? 0) === 0
        ? `NEW · ${p.after} ref${p.after === 1 ? "" : "s"}`
        : `+${p.after - p.before} refs`
    lines.push(
      `  ${mermaidId(p.from)}[${mermaidStr(p.from)}] -->|${mermaidStr(label)}| ${mermaidId(p.to)}[${mermaidStr(p.to)}]`,
    )
  }
  lines.push("```")
  return [
    "#### New cross-module dependencies",
    "",
    ...lines,
    "",
  ].join("\n")
}

function commentBody(report, repo, headSha, waivedBy, approvalHint) {
  const status =
    report.verdict === "fail"
      ? waivedBy
        ? `⚠️ failed — waived by @${waivedBy}'s approval`
        : "❌ failed"
      : "✅ passed"
  const parts = [
    COMMENT_MARKER,
    `### Semfora Gate ${status}`,
    "",
    `**${report.errors ?? 0}** policy error(s) · **${report.warnings ?? 0}** warning(s) · ${report.files_changed ?? 0} files, ${report.symbols_changed ?? 0} symbols changed · ${report.coupling_delta?.new_edges ?? 0} new cross-module edge(s)`,
    "",
  ]
  const denied = deniedDomains(report)
  if (report.verdict === "fail" && denied.length > 0 && !waivedBy) {
    parts.push(
      `> 🚫 **Denied by policy** — this PR edits restricted domain(s): **${denied.join(", ")}**. \`semfora.toml\` marks them protected at error severity, so the gate blocks this PR.${approvalHint}`,
      "",
    )
  }
  parts.push(
    findingsTable(report, repo, headSha),
    complexityChart(report),
    couplingGraph(report),
    `<sub>Semantic PR gate by <a href="https://semfora.ai">semfora.ai</a> — analysis runs entirely in your CI; your code never leaves your runner.</sub>`,
  )
  // GitHub caps comment bodies at 65536 chars; leave room for the frame.
  let body = parts.filter(Boolean).join("\n")
  if (body.length > 60000) {
    body = `${body.slice(0, 60000)}\n\n…truncated — see the full report in the workflow step summary.`
  }
  return body
}

// --- sticky comment --------------------------------------------------------------

async function findGateComment(token, repo, prNumber) {
  const comments = await ghPaged(token, `/repos/${repo}/issues/${prNumber}/comments`)
  return comments.find((c) => c.body?.includes(COMMENT_MARKER)) ?? null
}

async function upsertPrComment(token, repo, prNumber, existing, body) {
  const res = existing
    ? await gh(token, "PATCH", `/repos/${repo}/issues/comments/${existing.id}`, { body })
    : await gh(token, "POST", `/repos/${repo}/issues/${prNumber}/comments`, { body })
  if (!res.ok) {
    warn(
      `Semfora could not post the PR comment (HTTP ${res.status}). The ` +
        "github-token needs `pull-requests: write`.",
    )
  }
}

// --- inline line comments ----------------------------------------------------------

/**
 * file -> Set(new-side line numbers that are inside a diff hunk). GitHub
 * rejects review comments outside hunks, so hits elsewhere stay in the
 * sticky-comment table (still linked) instead of 422ing.
 */
async function commentableLines(token, repo, prNumber) {
  const map = new Map()
  const files = await ghPaged(token, `/repos/${repo}/pulls/${prNumber}/files`, { maxPages: 3 })
  for (const f of files) {
    if (!f.patch) continue
    const lines = new Set()
    let newLine = 0
    for (const raw of f.patch.split("\n")) {
      const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw)
      if (hunk) {
        newLine = Number(hunk[1])
        continue
      }
      if (raw.startsWith("+") || raw.startsWith(" ") || raw === "") {
        lines.add(newLine)
        newLine++
      }
      // "-" lines belong to the old side; "\ No newline" markers count for neither.
    }
    map.set(f.filename, lines)
  }
  return map
}

async function postLineComments(token, repo, pr, report) {
  const hits = (report.rule_hits ?? []).filter((h) => h.file && h.line).slice(0, 25)
  if (hits.length === 0) return
  const commentable = await commentableLines(token, repo, pr.number)
  const existing = new Set(
    (await ghPaged(token, `/repos/${repo}/pulls/${pr.number}/comments`, { maxPages: 5 }))
      .filter((c) => c.body?.includes(LINE_MARKER))
      .map((c) => `${c.path}:${c.line ?? c.original_line}`),
  )
  let failures = 0
  for (const h of hits) {
    if (!commentable.get(h.file)?.has(h.line)) continue
    if (existing.has(`${h.file}:${h.line}`)) continue
    const evidence = formatEvidence(h.evidence)
    const body = [
      LINE_MARKER,
      `**Semfora: ${h.rule}** (${h.severity})${h.groups?.length ? ` — domains: ${h.groups.join(", ")}` : ""}`,
      "",
      h.message,
      evidence ? `\n\`${evidence}\`` : "",
    ]
      .filter(Boolean)
      .join("\n")
    const res = await gh(token, "POST", `/repos/${repo}/pulls/${pr.number}/comments`, {
      commit_id: pr.head?.sha,
      path: h.file,
      line: h.line,
      side: "RIGHT",
      body,
    })
    if (!res.ok) failures++
  }
  if (failures > 0) {
    warn(
      `Semfora could not place ${failures} inline comment(s) — they remain ` +
        "in the gate report comment. The github-token needs `pull-requests: write`.",
    )
  }
}

// --- deny review (Changes Requested) ------------------------------------------------

async function syncDenyReview(token, repo, pr, denied, domains) {
  const reviews = await ghPaged(token, `/repos/${repo}/pulls/${pr.number}/reviews`)
  const active = reviews.filter(
    (r) => r.state === "CHANGES_REQUESTED" && r.body?.includes(REVIEW_MARKER),
  )
  if (denied) {
    if (active.length > 0) return // one standing deny review is enough
    const res = await gh(token, "POST", `/repos/${repo}/pulls/${pr.number}/reviews`, {
      event: "REQUEST_CHANGES",
      body: [
        REVIEW_MARKER,
        "🚫 **Semfora Gate denied this pull request.**",
        "",
        domains.length > 0
          ? `It edits restricted domain(s) protected by \`semfora.toml\`: **${domains.join(", ")}**.`
          : "It violates error-severity rules in `semfora.toml`.",
        "",
        "Details are in the gate report comment and inline annotations. This review is dismissed automatically when the gate passes or the failure is waived.",
      ].join("\n"),
    })
    if (!res.ok) {
      warn(`Semfora could not submit the deny review (HTTP ${res.status}).`)
    }
  } else {
    for (const r of active) {
      const res = await gh(token, "PUT", `/repos/${repo}/pulls/${pr.number}/reviews/${r.id}/dismissals`, {
        message: "Semfora gate passed (or the failure was waived) — dismissing the deny review.",
      })
      if (!res.ok) {
        warn(`Semfora could not dismiss its deny review (HTTP ${res.status}).`)
      }
    }
  }
}

// --- required reviewers / approvals ---------------------------------------------------

/**
 * Parse the reviewer inputs. Plain entries are usernames; entries containing
 * "/" are org teams (the org part is informational — GitHub keys team review
 * requests on the slug within the repo's own org). Returns null when neither
 * required-reviewers nor require-approval is configured.
 */
function reviewerConfig() {
  const entries = input("required-reviewers")
    .split(/[\s,]+/)
    .map((e) => e.replace(/^@/, ""))
    .filter(Boolean)
  const approvalRaw = input("require-approval").toLowerCase()
  const approvalMode =
    approvalRaw === "admin"
      ? "admin"
      : approvalRaw === "true" || approvalRaw === "reviewers"
        ? "reviewers"
        : "off"
  if (entries.length === 0 && approvalMode === "off") return null
  return {
    users: entries.filter((e) => !e.includes("/")),
    teams: entries.filter((e) => e.includes("/")).map((e) => e.split("/").pop()),
    requestOn: (input("request-reviewers-on") || "fail").toLowerCase(),
    approvalMode,
  }
}

/** true / false / null (=inconclusive: token can't see the collaborator list). */
async function isCollaborator(token, repo, username) {
  const res = await gh(token, "GET", `/repos/${repo}/collaborators/${encodeURIComponent(username)}`)
  if (res.status === 204) return true
  if (res.status === 404) return false
  return null
}

async function isRepoAdmin(token, repo, username) {
  const res = await gh(
    token,
    "GET",
    `/repos/${repo}/collaborators/${encodeURIComponent(username)}/permission`,
  )
  if (!res.ok) return false
  const data = await res.json()
  return data.permission === "admin" || data.role_name === "admin"
}

/**
 * Request the configured reviewers on the PR. Only people who actually have
 * access to the repo can review, so each username is validated as a
 * collaborator (covers org members with access AND outside contributors)
 * before it goes into the request; the rest get a warning explaining why.
 */
async function requestReviewers(token, repo, pr, cfg) {
  const author = pr.user?.login
  const alreadyRequested = new Set((pr.requested_reviewers ?? []).map((u) => u.login))
  const requestedTeams = new Set((pr.requested_teams ?? []).map((t) => t.slug))
  const reviews = await ghPaged(token, `/repos/${repo}/pulls/${pr.number}/reviews`)
  const alreadyReviewed = new Set(reviews.map((r) => r.user?.login).filter(Boolean))
  const owner = repo.split("/")[0]

  const users = []
  for (const username of cfg.users) {
    if (username === author) continue
    if (alreadyRequested.has(username) || alreadyReviewed.has(username)) continue
    const collab = await isCollaborator(token, repo, username)
    if (collab === false) {
      const orgRes = await gh(token, "GET", `/orgs/${owner}/members/${encodeURIComponent(username)}`)
      warn(
        orgRes.status === 204
          ? `Semfora: ${username} is a member of ${owner} but has no access to this repo — GitHub cannot request a review from them. Grant repo access first.`
          : `Semfora: ${username} is not a contributor on this repo or a member of its org — skipped as reviewer.`,
      )
      continue
    }
    // collab === null (inconclusive) falls through: let the request decide.
    users.push(username)
  }
  const teams = cfg.teams.filter((t) => !requestedTeams.has(t))
  if (users.length === 0 && teams.length === 0) return

  const res = await gh(token, "POST", `/repos/${repo}/pulls/${pr.number}/requested_reviewers`, {
    ...(users.length ? { reviewers: users } : {}),
    ...(teams.length ? { team_reviewers: teams } : {}),
  })
  if (res.ok) {
    notice(
      `Semfora requested review from: ${[...users, ...teams.map((t) => `team ${t}`)].join(", ")}.`,
    )
  } else {
    warn(
      `Semfora could not request reviewers (HTTP ${res.status}). The ` +
        "github-token needs `pull-requests: write` (and fork PRs get a " +
        "read-only token).",
    )
  }
}

/**
 * Return the login of a qualified approver whose LATEST review is an
 * approval of the PR's current head commit, or null. Stale approvals (older
 * commit) don't count — an approval must cover the code actually merging.
 * Mode "reviewers": approver must be in required-reviewers (or a member of
 * a listed team). Mode "admin": approver must have admin permission.
 */
async function findQualifiedApproval(token, repo, pr, cfg) {
  const reviews = await ghPaged(token, `/repos/${repo}/pulls/${pr.number}/reviews`)
  const headSha = pr.head?.sha
  const latest = new Map()
  for (const review of reviews) {
    const login = review.user?.login
    if (!login) continue
    if (["APPROVED", "CHANGES_REQUESTED", "DISMISSED"].includes(review.state)) {
      latest.set(login, review)
    }
  }
  const owner = repo.split("/")[0]
  for (const [login, review] of latest) {
    if (review.state !== "APPROVED") continue
    if (headSha && review.commit_id !== headSha) continue
    if (login === pr.user?.login) continue // self-approval never waives
    if (cfg.approvalMode === "admin") {
      if (await isRepoAdmin(token, repo, login)) return login
      continue
    }
    if (cfg.users.includes(login)) return login
    for (const team of cfg.teams) {
      const res = await gh(
        token,
        "GET",
        `/orgs/${owner}/teams/${team}/memberships/${encodeURIComponent(login)}`,
      )
      if (res.status === 200 && (await res.json()).state === "active") return login
    }
  }
  return null
}

// --- 3 + 4. run the gate and project the report ----------------------------------

async function main() {
  const key = input("semfora-key")
  if (!key) fail("The semfora-key input is required.")
  mask(key)
  const apiUrl = input("api-url") || "https://semfora.ai"
  requireHttps(apiUrl, "api-url")

  const event = readEvent()
  const pr = event.pull_request
  const base = input("base") || pr?.base?.sha || ""
  if (!base) {
    fail(
      "No base to gate against: set the `base` input, or run on a " +
        "pull_request event. Note: use actions/checkout with fetch-depth: 0 " +
        "so the base commit is present.",
    )
  }
  const targetRef = input("target-ref") || "HEAD"
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd()

  const verified = await verifyKey(apiUrl, key)
  const engine = await resolveEngine(verified)
  console.log(`Semfora engine ${verified.engineVersion} (plan: ${verified.plan})`)

  // The index is a prerequisite; its cost is the bulk of the run.
  execFileSync(engine, ["index", "generate", "."], {
    cwd: workspace,
    stdio: ["ignore", "ignore", "inherit"],
    timeout: 20 * 60 * 1000,
  })

  const summaryPath = path.join(
    process.env.RUNNER_TEMP || "/tmp",
    "semfora-gate-summary.md",
  )
  const args = [
    "ci",
    "--base",
    base,
    "--target-ref",
    targetRef,
    "--summary-md",
    summaryPath,
    "--format",
    "json",
  ]
  const result = await new Promise((resolvePromise) => {
    execFile(
      engine,
      args,
      { cwd: workspace, maxBuffer: 64 * 1024 * 1024, timeout: 25 * 60 * 1000 },
      (error, stdout) => resolvePromise({ code: error?.code ?? 0, stdout }),
    )
  })

  // Exit 20 = policy errors WITH a normal report; anything else nonzero is
  // an analysis failure (mirror of the cloud pipeline's contract).
  if (result.code !== 0 && result.code !== 20) {
    fail(`Semfora analysis failed (exit ${result.code}).`)
  }
  let report
  try {
    report = JSON.parse(result.stdout)
  } catch {
    fail("Semfora produced an unreadable report.")
  }

  const summaryMd = fs.existsSync(summaryPath)
    ? fs.readFileSync(summaryPath, "utf8")
    : ""
  if (summaryMd) appendSummary(summaryMd)
  for (const hit of report.rule_hits ?? []) {
    annotate(hit.severity === "error" ? "error" : "warning", {
      file: hit.file || undefined,
      line: hit.line || 1,
      title: `Semfora: ${hit.rule}`,
      message: `${hit.message}${
        hit.groups?.length ? ` (domains: ${hit.groups.join(", ")})` : ""
      }`,
    })
  }

  // PR surfaces. Shared degradation rule: anything that goes wrong here is
  // a warning, never a gate verdict — plumbing must not flip pass to fail.
  const reviewers = reviewerConfig()
  const token = input("github-token") || process.env.GITHUB_TOKEN || ""
  const repoSlug = process.env.GITHUB_REPOSITORY || ""
  const canUsePr = Boolean(pr?.number && repoSlug && token)
  let waivedBy = null

  if (reviewers) {
    if (!canUsePr) {
      warn(
        "Semfora: reviewer/approval inputs are set but this is not a pull " +
          "request run (or no github-token is available) — skipped.",
      )
    } else {
      try {
        const shouldRequest =
          (reviewers.users.length > 0 || reviewers.teams.length > 0) &&
          (reviewers.requestOn === "always" ||
            (reviewers.requestOn === "fail" && report.verdict === "fail"))
        if (shouldRequest) await requestReviewers(token, repoSlug, pr, reviewers)
        if (reviewers.approvalMode !== "off" && report.verdict === "fail") {
          waivedBy = await findQualifiedApproval(token, repoSlug, pr, reviewers)
        }
      } catch (e) {
        warn(`Semfora reviewer step failed: ${e.message}`)
      }
    }
  }

  if (canUsePr) {
    // Inline comments on the exact lines the rules hit.
    if ((input("line-comments") || "true").toLowerCase() !== "false") {
      try {
        await postLineComments(token, repoSlug, pr, report)
      } catch (e) {
        warn(`Semfora inline comments failed: ${e.message}`)
      }
    }

    // Deny review: Changes Requested while the policy verdict stands,
    // dismissed once the gate passes or the failure is waived.
    if ((input("request-changes") || "true").toLowerCase() !== "false") {
      try {
        const denied = report.verdict === "fail" && !waivedBy
        await syncDenyReview(token, repoSlug, pr, denied, deniedDomains(report))
      } catch (e) {
        warn(`Semfora deny review failed: ${e.message}`)
      }
    }

    // Sticky comment: linked findings, complexity chart, dependency graph.
    const commentMode = (input("pr-comment") || "on-findings").toLowerCase()
    if (commentMode !== "never") {
      try {
        const hasFindings = (report.errors ?? 0) + (report.warnings ?? 0) > 0
        const existing = await findGateComment(token, repoSlug, pr.number)
        // on-findings: create only when there is something to say, but always
        // refresh an existing comment so a stale failure never lingers.
        if (commentMode === "always" || hasFindings || existing) {
          const approvalHint =
            reviewers?.approvalMode === "admin"
              ? " An approval of the current head commit from a repo admin waives this."
              : reviewers?.approvalMode === "reviewers"
                ? ` An approval of the current head commit from a required reviewer (${[
                    ...reviewers.users,
                    ...reviewers.teams.map((t) => `team ${t}`),
                  ].join(", ")}) waives this.`
                : ""
          await upsertPrComment(
            token,
            repoSlug,
            pr.number,
            existing,
            commentBody(report, repoSlug, pr.head?.sha, waivedBy, approvalHint),
          )
        }
      } catch (e) {
        warn(`Semfora PR comment failed: ${e.message}`)
      }
    }
  }

  setOutput("verdict", report.verdict ?? "pass")
  setOutput("errors", report.errors ?? 0)
  setOutput("warnings", report.warnings ?? 0)
  setOutput("waived", waivedBy ? "true" : "false")
  setOutput("denied-domains", deniedDomains(report).join(","))

  if (report.verdict === "fail") {
    if (waivedBy) {
      appendSummary(
        `> ✅ **Waived** — ${report.errors} policy error(s) approved by @${waivedBy} at the current head commit.`,
      )
      notice(
        `Semfora gate: ${report.errors} policy error(s) waived by @${waivedBy}'s approval.`,
      )
    } else {
      const unblock =
        reviewers?.approvalMode === "admin"
          ? " An approval of the current head commit from a repo admin waives this failure — the check re-runs on review via the pull_request_review trigger."
          : reviewers?.approvalMode === "reviewers"
            ? ` An approval of the current head commit from one of the required reviewers (${[
                ...reviewers.users,
                ...reviewers.teams.map((t) => `team ${t}`),
              ].join(", ")}) waives this failure — the check re-runs on review via the pull_request_review trigger.`
            : ""
      fail(
        `Semfora gate failed: ${report.errors} policy error(s), ` +
          `${report.warnings} warning(s). See the step summary for details.${unblock}`,
      )
    }
  }
  console.log(
    `Semfora gate passed (${report.warnings ?? 0} warnings, ` +
      `${report.files_changed ?? 0} files changed).`,
  )
}

main().catch((e) => fail(e.message))
