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
//   5. Required reviewers (optional): request the configured org members /
//      contributors as reviewers on the PR, and — with require-approval —
//      let one of them approving the current head commit waive a policy
//      failure. Marking this check "required" in branch protection makes
//      those people de-facto required reviewers for protected changes.
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

// --- 5. required reviewers -------------------------------------------------------

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

/**
 * Parse the required-reviewers input. Plain entries are usernames; entries
 * containing "/" are org teams (the org part is informational — GitHub keys
 * team review requests on the slug within the repo's own org).
 */
function reviewerConfig() {
  const entries = input("required-reviewers")
    .split(/[\s,]+/)
    .map((e) => e.replace(/^@/, ""))
    .filter(Boolean)
  if (entries.length === 0) return null
  return {
    users: entries.filter((e) => !e.includes("/")),
    teams: entries.filter((e) => e.includes("/")).map((e) => e.split("/").pop()),
    requestOn: (input("request-reviewers-on") || "fail").toLowerCase(),
    requireApproval: input("require-approval").toLowerCase() === "true",
  }
}

async function listReviews(token, repo, prNumber) {
  const reviews = []
  for (let page = 1; page <= 10; page++) {
    const res = await gh(
      token,
      "GET",
      `/repos/${repo}/pulls/${prNumber}/reviews?per_page=100&page=${page}`,
    )
    if (!res.ok) break
    const batch = await res.json()
    reviews.push(...batch)
    if (batch.length < 100) break
  }
  return reviews
}

/** true / false / null (=inconclusive: token can't see the collaborator list). */
async function isCollaborator(token, repo, username) {
  const res = await gh(token, "GET", `/repos/${repo}/collaborators/${encodeURIComponent(username)}`)
  if (res.status === 204) return true
  if (res.status === 404) return false
  return null
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
  const reviews = await listReviews(token, repo, pr.number)
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
 * Return the login of a required reviewer whose LATEST review is an approval
 * of the PR's current head commit, or null. Stale approvals (older commit)
 * don't count — an approval must cover the code actually being merged.
 */
async function findQualifiedApproval(token, repo, pr, cfg) {
  const reviews = await listReviews(token, repo, pr.number)
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

  if (fs.existsSync(summaryPath)) {
    appendSummary(fs.readFileSync(summaryPath, "utf8"))
  }
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

  // Reviewers: request + (optionally) waive on approval. Failures here are
  // warnings, never gate verdicts — the reviewer plumbing must not be able
  // to flip a pass to a fail.
  const reviewers = reviewerConfig()
  const token = input("github-token") || process.env.GITHUB_TOKEN || ""
  const repoSlug = process.env.GITHUB_REPOSITORY || ""
  let waivedBy = null
  if (reviewers) {
    if (!pr || !pr.number || !repoSlug) {
      warn("Semfora: required-reviewers is set but this is not a pull request run — skipped.")
    } else if (!token) {
      warn("Semfora: required-reviewers is set but no github-token is available — skipped.")
    } else {
      try {
        const shouldRequest =
          reviewers.requestOn === "always" ||
          (reviewers.requestOn === "fail" && report.verdict === "fail")
        if (shouldRequest) await requestReviewers(token, repoSlug, pr, reviewers)
        if (reviewers.requireApproval && report.verdict === "fail") {
          waivedBy = await findQualifiedApproval(token, repoSlug, pr, reviewers)
        }
      } catch (e) {
        warn(`Semfora reviewer step failed: ${e.message}`)
      }
    }
  }

  setOutput("verdict", report.verdict ?? "pass")
  setOutput("errors", report.errors ?? 0)
  setOutput("warnings", report.warnings ?? 0)
  setOutput("waived", waivedBy ? "true" : "false")

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
        reviewers?.requireApproval && pr
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
