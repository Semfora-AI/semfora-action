// ---------------------------------------------------------------------------
// Semfora Gate — GitHub Action entry point (SEM-226, cloud-gate rework).
//
// Deliberately dependency-free (no @actions/* toolkit): everything below is
// plain Node 20 against the documented Actions contracts (INPUT_* env,
// workflow commands on stdout, GITHUB_OUTPUT / GITHUB_STEP_SUMMARY files).
// A security-tool action should be auditable in one file.
//
// The action is a THIN CLIENT — no engine binary ever reaches this runner,
// and the runner analyzes nothing (a checkout step isn't even required):
//   1. POST /api/gate/enqueue on semfora.ai with the license key + PR
//      coordinates. Semfora verifies the key AND that the key's billing
//      account owns this repo, then queues the gate run in its isolated
//      analysis pipeline (the same one that powers the dashboard). The
//      pipeline clones via the repo's Semfora GitHub App installation —
//      the repo must be connected on semfora.ai.
//   2. Poll /api/gate/status until the run finishes. The response is the
//      distilled gate report: verdict, rule hits, coupling — symbol NAMES
//      and NUMBERS only, never source.
//   3. Project the report: step summary (markdown), inline annotations
//      (::error/::warning file=), and action outputs.
//   4. PR surfaces (optional, all degrade to warnings — they can never flip
//      the gate verdict):
//      - sticky comment with linked findings, the domains the PR touches
//        (colored chips — the SAME deterministic colors semfora.ai assigns
//        those domains, see the ported registry below), a quality-impact
//        delta, a complexity chart, and a cross-module dependency graph
//        (Mermaid — GitHub renders it);
//      - inline review comments on the exact lines the rules hit;
//      - a Changes Requested review when policy denies the PR (restricted
//        domains in semfora.toml), dismissed automatically once the gate
//        passes or is waived;
//      - required reviewers: request the configured org members /
//        contributors, and let an approval of the current head commit waive
//        a policy failure. require-approval: "admin" restricts the waiver
//        to repo admins.
//      - require-reason: keep a failing gate red until someone explains the
//        change in a PR comment mentioning @semfora (PR author or a repo
//        collaborator). The comment re-runs the gate (issue_comment runs
//        attach their checks to the DEFAULT branch, so the comment run only
//        re-triggers the failed pull_request run — the verdict flips in PR
//        context), and the accepted reason is persisted to semfora.ai
//        alongside the denied domains / quality regression it justifies.
// ---------------------------------------------------------------------------

const fs = require("node:fs")

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

// --- 1. cloud gate: enqueue + poll ---------------------------------------------

async function gateApi(apiUrl, pathname, body) {
  let res
  try {
    res = await fetchWithRetry(`${apiUrl.replace(/\/$/, "")}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
  } catch (e) {
    fail(`Could not reach Semfora (${pathname}): ${e.message}.`)
  }
  if (res.status === 403) {
    fail(
      "Semfora rejected the request: the license key is invalid, or it " +
        "does not belong to the account that owns this repository on " +
        "semfora.ai. Gate runs are available to licensed customers for " +
        "their own connected repos — https://semfora.ai.",
    )
  }
  if (!res.ok) {
    let detail = ""
    try {
      detail = (await res.json()).error ?? ""
    } catch {
      /* body optional */
    }
    fail(`Semfora gate API failed (${res.status}${detail ? `: ${detail}` : ""}).`)
  }
  return res.json()
}

/** Poll until the run settles. Backoff: 5s for the first minute, then 15s. */
async function waitForVerdict(apiUrl, key, runId, timeoutMs) {
  const started = Date.now()
  let polls = 0
  for (;;) {
    const elapsed = Date.now() - started
    if (elapsed > timeoutMs) {
      fail(
        `Semfora gate run did not finish within ${Math.round(timeoutMs / 60000)} ` +
          "minutes. Large first-time indexes can take longer — raise " +
          "poll-timeout-minutes, or check the run on the semfora.ai dashboard.",
      )
    }
    const status = await gateApi(apiUrl, "/api/gate/status", { key, runId })
    if (status.status === "SUCCEEDED") return status
    if (status.status === "FAILED" || status.status === "CANCELED") {
      fail(
        `Semfora analysis ${status.status.toLowerCase()}${
          status.errorMessage ? `: ${status.errorMessage}` : ""
        }`,
      )
    }
    polls++
    if (polls === 1) notice("Semfora gate queued — analyzing in Semfora's pipeline…")
    await new Promise((r) => setTimeout(r, elapsed < 60_000 ? 5_000 : 15_000))
  }
}

/**
 * Adapt the API's distilled gate report (camelCase CiMetrics) to the shape
 * the renderer below consumes (the engine's snake_case ci_report — kept so
 * the entire PR-surface renderer is unchanged from the local-run era).
 */
function toReport(ci) {
  return {
    verdict: ci.verdict === "fail" ? "fail" : "pass",
    gate_active: ci.gateActive === true,
    errors: ci.errors ?? 0,
    warnings: ci.warnings ?? 0,
    rule_hits: Array.isArray(ci.ruleHits) ? ci.ruleHits : [],
    rule_hits_total: ci.ruleHitsTotal ?? (ci.ruleHits?.length || 0),
    files_changed: ci.filesChanged ?? 0,
    symbols_changed: ci.symbolsChanged ?? 0,
    groups_touched: Array.isArray(ci.groupsTouched)
      ? ci.groupsTouched
          .map((g) => ({
            name: typeof g?.name === "string" ? g.name : "",
            symbols_changed: g?.symbolsChanged ?? 0,
          }))
          .filter((g) => g.name)
      : [],
    coupling_delta: ci.couplingDelta
      ? {
          new_edges: ci.couplingDelta.newEdges ?? 0,
          removed_edges: ci.couplingDelta.removedEdges ?? 0,
          net_change: ci.couplingDelta.netChange ?? 0,
          pairs: ci.couplingDelta.pairs ?? [],
        }
      : undefined,
    summary_md: ci.summaryMd ?? "",
  }
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

// --- domain identity colors (ported from semfora-web domain-chip.tsx) ----------
//
// Every domain gets a GENERATED color: golden-angle hue distribution in
// OKLCH, anchored at the brand emerald, with fixed lightness/chroma so all
// domain accents sit in one muted band. The registry is deterministic per
// repo — the canonical domain list (vended by /api/gate/status from the
// repo's semfora.toml groups) claims hues in sorted order, extra domains
// extend the sequence — so a domain is the SAME color on this PR comment as
// on every semfora.ai dashboard page. Constants and ordering rules must stay
// in lockstep with semfora-web/src/components/sentry/domain-chip.tsx.

/** Golden angle: consecutive indices land far apart on the hue wheel. */
const GOLDEN_ANGLE = 137.508
/** Brand emerald (#15BA81) sits near hue 166 in OKLCH. */
const BASE_HUE = 166

/** Hue for the nth canonical domain. */
function domainHue(index) {
  return (BASE_HUE + index * GOLDEN_ANGLE) % 360
}

/**
 * The web's one accent band is oklch(0.63 0.11 hue); GitHub markdown and
 * Mermaid want hex, so convert OKLCH → linear sRGB → gamma sRGB here. At
 * this lightness/chroma every hue is inside the sRGB gamut, so the clamp is
 * a formality and the hex is the same color the dashboard renders.
 */
function hueToHex(hue) {
  const rad = (hue * Math.PI) / 180
  const L = 0.63
  const a = 0.11 * Math.cos(rad)
  const b = 0.11 * Math.sin(rad)
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3
  const channels = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ]
  const hex = channels
    .map((c) => {
      const lin = Math.min(1, Math.max(0, c))
      const srgb = lin <= 0.0031308 ? 12.92 * lin : 1.055 * lin ** (1 / 2.4) - 0.055
      return Math.round(srgb * 255)
        .toString(16)
        .padStart(2, "0")
    })
    .join("")
  return `#${hex}`
}

/** Hash fallback for domains outside any registry: stable hue from the
 *  name — the identical hash the web uses. */
function domainFallbackColor(domain) {
  let hash = 0
  for (let i = 0; i < domain.length; i++) {
    hash = (hash * 31 + domain.charCodeAt(i)) | 0
  }
  return hueToHex(Math.abs(hash) % 360)
}

function aliasLookup(key, colors) {
  const exact = colors.get(key)
  if (exact) return exact
  for (const [name, color] of colors) {
    if (key.includes(name) || name.includes(key)) return color
  }
  return undefined
}

/** The repo's canonical color registry: canonical domains (sorted) claim
 *  hues first, extra domains extend the sequence. */
function canonicalDomainColors(groupNames, extraDomains = []) {
  const colors = new Map()
  const canonical = [...new Set(groupNames.map((n) => n.toLowerCase()))].sort()
  canonical.forEach((name, i) => {
    colors.set(name, hueToHex(domainHue(i)))
  })
  const extras = [...new Set(extraDomains.map((d) => d.toLowerCase()))]
    .filter((d) => !aliasLookup(d, colors))
    .sort()
  extras.forEach((name, i) => {
    colors.set(name, hueToHex(domainHue(canonical.length + i)))
  })
  return colors
}

/** Resolve a domain's color: exact registry hit, fuzzy alias, then the
 *  hash fallback. */
function domainColorFor(domain, colors) {
  if (colors) {
    const hit = aliasLookup(domain.toLowerCase(), colors)
    if (hit) return hit
  }
  return domainFallbackColor(domain)
}

/** Registry for this report: the repo's canonical domains claim hues in
 *  sorted order (matching the dashboard); domains that appear only in this
 *  report extend the sequence. */
function buildDomainColors(report, canonicalDomains) {
  const extras = new Set()
  for (const g of report.groups_touched ?? []) extras.add(g.name)
  for (const h of report.rule_hits ?? []) {
    for (const d of h.groups ?? []) extras.add(d)
  }
  return canonicalDomainColors(canonicalDomains, [...extras])
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

/**
 * The domains this PR touches, as colored chips — Mermaid nodes whose fill
 * is each domain's canonical color, so the chips match the semfora.ai
 * dashboard exactly.
 */
function domainsSection(report, colors) {
  const touched = report.groups_touched ?? []
  if (touched.length === 0) return ""
  const shown = touched.slice(0, 12)
  const lines = ["```mermaid", "graph LR"]
  shown.forEach((g, i) => {
    const color = domainColorFor(g.name, colors)
    const label = `${g.name} · ${g.symbols_changed} symbol${g.symbols_changed === 1 ? "" : "s"}`
    lines.push(`  d${i}(${mermaidStr(label)}):::d${i}`)
    lines.push(`  classDef d${i} fill:${color},stroke:${color},color:#fff`)
  })
  lines.push("```")
  const more =
    touched.length > shown.length
      ? `\n_…and ${touched.length - shown.length} more domain(s)._`
      : ""
  return ["#### Domains touched", "", ...lines, more, ""].filter(Boolean).join("\n")
}

function fmtSigned(n) {
  return n > 0 ? `+${n}` : `${n}`
}

/** Summed cognitive-complexity increase across over-budget symbols. */
function complexityDeltaOf(report) {
  return (report.rule_hits ?? [])
    .filter((h) => h.rule === "complexity" && h.evidence?.cc !== undefined)
    .reduce((sum, h) => sum + (h.evidence.cc - (h.evidence.cc_before ?? 0)), 0)
}

/**
 * The PR's measured quality delta over its base — cross-module coupling and
 * cognitive complexity — plus the repo's current Vital Score (from the
 * latest default-branch analysis) as context. Only renders rows the data
 * actually supports; a PR with no measured movement gets no section.
 */
function qualitySection(report, repoVital) {
  const rows = []
  const cd = report.coupling_delta
  if (cd && (cd.new_edges || cd.removed_edges || cd.net_change)) {
    const arrow = cd.net_change > 0 ? "▲" : cd.net_change < 0 ? "▼" : "—"
    rows.push(
      `| Cross-module coupling | ${arrow} ${fmtSigned(cd.net_change)} ref(s) · ${cd.new_edges} new edge(s), ${cd.removed_edges} removed |`,
    )
  }
  const compHits = (report.rule_hits ?? []).filter(
    (h) => h.rule === "complexity" && h.evidence?.cc !== undefined,
  )
  const ccDelta = complexityDeltaOf(report)
  if (compHits.length > 0 && ccDelta !== 0) {
    rows.push(
      `| Cognitive complexity | ${ccDelta > 0 ? "▲" : "▼"} ${fmtSigned(ccDelta)} across ${compHits.length} symbol(s) over budget |`,
    )
  }
  if (repoVital) {
    rows.push(
      `| Codebase Vital Score | ${Math.round(repoVital.svs)}${repoVital.grade ? ` (${repoVital.grade})` : ""} on the default branch |`,
    )
  }
  if (rows.length === 0) return ""
  return ["#### Quality impact", "", "| Metric | This PR |", "|---|---|", ...rows, ""].join(
    "\n",
  )
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

function commentBody(report, repo, headSha, waiver, approvalHint, extras = {}) {
  const { domainColors, repoVital } = extras
  const w = waiver ?? {}
  const waivedVia = [
    w.approvedBy ? `approved by @${w.approvedBy}` : "",
    w.reason ? `reason from @${w.reason.author}` : "",
  ]
    .filter(Boolean)
    .join(" · ")
  const status =
    report.verdict === "fail"
      ? w.waived
        ? `⚠️ failed — waived (${waivedVia})`
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
  if (report.verdict === "fail" && denied.length > 0 && !w.waived) {
    parts.push(
      `> 🚫 **Denied by policy** — this PR edits restricted domain(s): **${denied.join(", ")}**. \`semfora.toml\` marks them protected at error severity, so the gate blocks this PR.${approvalHint}`,
      "",
    )
  }
  if (report.verdict === "fail" && !w.waived && w.needsReason && !w.reason) {
    parts.push(
      `> ✍️ **Reason required** — comment \`@semfora <why this change is needed>\` on this PR (PR author or a repo collaborator, ${MIN_REASON_LENGTH}+ characters). The comment re-runs the gate, and the accepted reason is recorded on semfora.ai with the domains and quality deltas it covers.`,
      "",
    )
  }
  parts.push(
    qualitySection(report, repoVital),
    domainsSection(report, domainColors),
    findingsTable(report, repo, headSha),
    complexityChart(report),
    couplingGraph(report),
    `<sub>Semantic PR gate by <a href="https://semfora.ai">semfora.ai</a> — analyzed in Semfora's isolated pipeline via your GitHub App connection; this report contains symbol names and numbers only, never source.</sub>`,
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

/** New (deduplicated, diff-hunk-aware) inline comments for the rule hits. */
async function buildInlineComments(token, repo, pr, report) {
  const hits = (report.rule_hits ?? []).filter((h) => h.file && h.line).slice(0, 25)
  if (hits.length === 0) return []
  const commentable = await commentableLines(token, repo, pr.number)
  const existing = new Set(
    (await ghPaged(token, `/repos/${repo}/pulls/${pr.number}/comments`, { maxPages: 5 }))
      .filter((c) => c.body?.includes(LINE_MARKER))
      .map((c) => `${c.path}:${c.line ?? c.original_line}`),
  )
  const comments = []
  for (const h of hits) {
    if (!commentable.get(h.file)?.has(h.line)) continue
    if (existing.has(`${h.file}:${h.line}`)) continue
    const evidence = formatEvidence(h.evidence)
    comments.push({
      path: h.file,
      line: h.line,
      side: "RIGHT",
      body: [
        LINE_MARKER,
        `**Semfora: ${h.rule}** (${h.severity})${h.groups?.length ? ` — domains: ${h.groups.join(", ")}` : ""}`,
        "",
        h.message,
        evidence ? `\n\`${evidence}\`` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    })
  }
  return comments
}

// --- the gate review ----------------------------------------------------------------

/**
 * ONE review per verdict, not one message per finding: the deny verdict
 * (Changes Requested) and the inline line comments ride the same review —
 * the way a human reviewer's feedback lands — and the review is dismissed
 * once the gate passes or the failure is waived. Full details live in the
 * sticky report comment; the review body stays to one line.
 */
async function syncGateReview(token, repo, pr, report, { denied, domains, lineComments }) {
  const reviews = await ghPaged(token, `/repos/${repo}/pulls/${pr.number}/reviews`)
  const activeDeny = reviews.filter(
    (r) => r.state === "CHANGES_REQUESTED" && r.body?.includes(REVIEW_MARKER),
  )

  if (!denied) {
    for (const r of activeDeny) {
      const res = await gh(
        token,
        "PUT",
        `/repos/${repo}/pulls/${pr.number}/reviews/${r.id}/dismissals`,
        {
          message:
            "Semfora gate passed (or the failure was waived) — dismissing the deny review.",
        },
      )
      if (!res.ok) warn(`Semfora could not dismiss its deny review (HTTP ${res.status}).`)
    }
  }

  const comments = lineComments ? await buildInlineComments(token, repo, pr, report) : []
  const needDeny = denied && activeDeny.length === 0
  if (!needDeny && comments.length === 0) return

  const body = needDeny
    ? [
        REVIEW_MARKER,
        `🚫 **Semfora Gate denied this pull request**${
          domains.length > 0 ? ` — it edits restricted domain(s): **${domains.join(", ")}**` : ""
        }. Findings are annotated inline; details are in the gate report comment. Dismissed automatically when the gate passes or is waived.`,
      ].join("\n")
    : `⚠️ **Semfora Gate** — ${comments.length} finding(s) annotated inline; details are in the gate report comment.`

  const payload = {
    ...(pr.head?.sha ? { commit_id: pr.head.sha } : {}),
    event: needDeny ? "REQUEST_CHANGES" : "COMMENT",
    body,
    ...(comments.length ? { comments } : {}),
  }
  const res = await gh(token, "POST", `/repos/${repo}/pulls/${pr.number}/reviews`, payload)
  if (res.ok) return

  if (needDeny && comments.length > 0) {
    // A single out-of-range comment 422s the whole review — land the deny
    // verdict alone; the findings stay linked in the report comment.
    const retry = await gh(token, "POST", `/repos/${repo}/pulls/${pr.number}/reviews`, {
      ...(pr.head?.sha ? { commit_id: pr.head.sha } : {}),
      event: "REQUEST_CHANGES",
      body,
    })
    if (retry.ok) {
      warn(
        `Semfora could not attach ${comments.length} inline comment(s) ` +
          `(HTTP ${res.status}) — they remain in the gate report comment.`,
      )
      return
    }
  }
  warn(
    `Semfora could not submit the gate review (HTTP ${res.status}). The ` +
      "github-token needs `pull-requests: write`.",
  )
}

// --- change reasons (require-reason) ---------------------------------------------------

const REASON_MENTION = /@semfora\b/i
const MIN_REASON_LENGTH = 10
/** Comment authors who may unblock the gate with a reason (plus the PR
 *  author — on fork PRs the outside contributor IS the one who must
 *  explain the change). */
const REASON_ASSOCIATIONS = new Set(["OWNER", "MEMBER", "COLLABORATOR"])

/**
 * Extract the reason from a comment body. Returns null when the comment is
 * not addressed to @semfora at all, "" when it mentions @semfora but says
 * nothing usable (a bare tag is not a reason), else the reason text with
 * the mention stripped.
 */
function parseReason(body) {
  if (!REASON_MENTION.test(body ?? "")) return null
  const text = String(body)
    .replace(/@semfora\b/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
  return text.length >= MIN_REASON_LENGTH ? text : ""
}

function qualifiedCommenter(comment, pr) {
  const login = comment?.user?.login
  if (!login || comment?.user?.type === "Bot") return false
  return (
    login === pr?.user?.login ||
    REASON_ASSOCIATIONS.has(comment?.author_association)
  )
}

/**
 * The newest qualifying @semfora reason comment on the PR, or null. Our own
 * report comment is skipped by marker; bots never qualify.
 */
async function findReasonComment(token, repo, pr) {
  const comments = await ghPaged(token, `/repos/${repo}/issues/${pr.number}/comments`)
  let best = null
  for (const c of comments) {
    if (c.body?.includes(COMMENT_MARKER)) continue
    const reason = parseReason(c.body ?? "")
    if (!reason) continue
    if (!qualifiedCommenter(c, pr)) continue
    if (!best || Date.parse(c.created_at ?? 0) >= Date.parse(best.created_at ?? 0)) {
      best = { reason, author: c.user.login, url: c.html_url ?? "", created_at: c.created_at }
    }
  }
  return best
}

/**
 * Which conditions unblock a failing verdict, and whether they all hold.
 * Every CONFIGURED waiver must be satisfied: with require-approval and
 * require-reason both on, a failure needs the approval AND the reason.
 * With neither configured a failure is simply a failure.
 */
function resolveWaiver({ verdict, approvalMode, requireReason, approvedBy, reason }) {
  const missing = []
  if (approvalMode !== "off" && !approvedBy) missing.push("approval")
  if (requireReason && !reason) missing.push("reason")
  const configured = approvalMode !== "off" || requireReason
  return {
    waived: verdict === "fail" && configured && missing.length === 0,
    missing,
    approvedBy: approvedBy ?? null,
    reason: reason ?? null,
    needsReason: requireReason,
  }
}

/** "owner/repo/.github/workflows/gate.yml@refs/heads/main" → workflow path. */
function workflowPathFromRef(ref) {
  const path = String(ref ?? "").split("@")[0]
  const parts = path.split("/")
  return parts.length > 2 ? parts.slice(2).join("/") : ""
}

/**
 * Best-effort: persist the accepted reason to semfora.ai, tied to the gate
 * run and to what it justified (denied domains, coupling/complexity
 * regression — names and numbers; the reason text is the commenter's own
 * words). Never affects the verdict.
 */
async function postReason(apiUrl, key, payload) {
  try {
    const res = await fetchWithRetry(
      `${apiUrl.replace(/\/$/, "")}/api/gate/reason`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key, ...payload }),
      },
      { attempts: 2 },
    )
    // Older servers 404 this path into the SPA (200 + HTML) — only a JSON
    // { ok: true } counts as recorded.
    const ack = res.ok ? await res.json().catch(() => null) : null
    if (ack?.ok) {
      notice(`Semfora recorded the change reason from @${payload.author} on semfora.ai.`)
    } else {
      warn(`Semfora could not record the change reason (HTTP ${res.status}).`)
    }
  } catch (e) {
    warn(`Semfora could not record the change reason: ${e.message}`)
  }
}

/**
 * issue_comment run: not a gate run. Validate the @semfora reason comment,
 * then re-run the failed pull_request run of THIS workflow at the PR head —
 * that re-run executes in PR context (where check runs actually attach to
 * the PR; issue_comment checks land on the default branch), finds the
 * reason comment, waives the failure, and persists the reason. This run
 * itself always exits green — a red comment-run check would only confuse.
 */
async function runFromReasonComment(event, repoSlug) {
  if ((input("require-reason") || "false").toLowerCase() !== "true") {
    notice("Semfora: issue_comment received but require-reason is off — nothing to do.")
    return
  }
  const reason = parseReason(event.comment?.body ?? "")
  if (reason === null) return // not addressed to @semfora
  if (reason === "") {
    notice(
      `Semfora: the @semfora comment needs an actual reason (at least ${MIN_REASON_LENGTH} characters) to unblock the gate.`,
    )
    return
  }
  const token = input("github-token") || process.env.GITHUB_TOKEN || ""
  if (!token) {
    warn("Semfora: no github-token available on the issue_comment run — cannot re-run the gate.")
    return
  }
  const prNumber = event.issue?.number
  const prRes = await gh(token, "GET", `/repos/${repoSlug}/pulls/${prNumber}`)
  if (!prRes.ok) {
    warn(`Semfora could not load PR #${prNumber} (HTTP ${prRes.status}).`)
    return
  }
  const pr = await prRes.json()
  if (!qualifiedCommenter(event.comment, pr)) {
    notice(
      `Semfora: @${event.comment?.user?.login ?? "?"} is neither the PR author nor a repo collaborator — the reason does not unblock the gate.`,
    )
    return
  }
  const wfPath = workflowPathFromRef(process.env.GITHUB_WORKFLOW_REF)
  const runsRes = await gh(
    token,
    "GET",
    `/repos/${repoSlug}/actions/runs?event=pull_request&head_sha=${encodeURIComponent(pr.head?.sha ?? "")}&per_page=100`,
  )
  if (!runsRes.ok) {
    warn(
      `Semfora could not list workflow runs (HTTP ${runsRes.status}) — the ` +
        "issue_comment job needs `actions: write` in its permissions.",
    )
    return
  }
  const runs = ((await runsRes.json()).workflow_runs ?? []).filter(
    (r) => !wfPath || r.path === wfPath,
  )
  const latest = runs[0] // the API lists newest first
  if (!latest) {
    warn(
      "Semfora: no pull_request gate run found at the PR head — the reason " +
        "will apply on the next gate run.",
    )
    return
  }
  if (latest.status !== "completed") {
    notice("Semfora: the gate is already running — it will pick up this reason.")
    return
  }
  if (latest.conclusion === "success") {
    notice("Semfora: the gate already passes — nothing to re-run.")
    return
  }
  const rerun = await gh(
    token,
    "POST",
    `/repos/${repoSlug}/actions/runs/${latest.id}/rerun-failed-jobs`,
  )
  if (rerun.ok) {
    notice(
      `Semfora: reason received from @${event.comment.user.login} — re-running the gate to apply it.`,
    )
  } else {
    warn(
      `Semfora could not re-run the gate (HTTP ${rerun.status}). The ` +
        "issue_comment job needs `actions: write` in its permissions.",
    )
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

  // Removed inputs from the local-run era: fail loudly rather than let a
  // workflow believe an unsupported knob still does something.
  if (input("engine-path")) {
    fail(
      "engine-path is no longer supported: gate analysis runs in Semfora's " +
        "cloud pipeline, not on this runner. Remove the input (and any " +
        "checkout/fetch-depth plumbing that only existed for it).",
    )
  }
  if (input("target-ref") && input("target-ref") !== "HEAD") {
    fail(
      "target-ref is no longer supported: the cloud gate analyzes the " +
        "pushed PR head, so uncommitted-changes gating (WORKING) is not " +
        "available. Remove the input.",
    )
  }

  const event = readEvent()
  const repoSlug = process.env.GITHUB_REPOSITORY || ""
  if (!repoSlug) fail("GITHUB_REPOSITORY is not set — not a GitHub Actions run?")

  // issue_comment runs are reason-relay runs, never gate runs: validate the
  // @semfora comment and re-trigger the failed pull_request run (checks from
  // comment runs attach to the default branch, so the verdict must flip in
  // PR context). Always exits green.
  if (event.comment && event.issue) {
    // Comments on plain issues are none of our business — but they must
    // exit green, not fall through to "no base to gate against".
    if (event.issue.pull_request) await runFromReasonComment(event, repoSlug)
    return
  }

  const pr = event.pull_request
  const base = input("base") || pr?.base?.sha || ""
  if (!base) {
    fail(
      "No base to gate against: set the `base` input, or run on a " +
        "pull_request event.",
    )
  }
  const headSha = pr?.head?.sha || process.env.GITHUB_SHA || ""

  const timeoutMinutes = Number(input("poll-timeout-minutes")) || 20
  const enqueued = await gateApi(apiUrl, "/api/gate/enqueue", {
    key,
    repo: repoSlug,
    baseSha: base,
    headSha: headSha || undefined,
    prNumber: pr?.number,
    headRef: pr?.head?.ref,
    baseRef: pr?.base?.ref,
  })
  console.log(
    `Semfora gate run ${enqueued.runId}${enqueued.reused ? " (reusing an in-flight run for this head)" : ""}`,
  )

  const settled = await waitForVerdict(
    apiUrl,
    key,
    enqueued.runId,
    timeoutMinutes * 60 * 1000,
  )
  if (!settled.ci) {
    fail(
      "The run finished but produced no gate report — the repo's analysis " +
        "pipeline may predate the gate. Contact support@semfora.ai.",
    )
  }
  const report = toReport(settled.ci)

  // Canonical domain list + repo Vital Score, vended by the status endpoint
  // (newer servers only — everything below degrades to the hash-fallback
  // colors and no score row when absent).
  const canonicalDomains = Array.isArray(settled.domains)
    ? settled.domains.filter((d) => typeof d === "string" && d)
    : []
  const repoVital =
    settled.repoVital && typeof settled.repoVital.svs === "number"
      ? { svs: settled.repoVital.svs, grade: String(settled.repoVital.grade ?? "") }
      : null
  const domainColors = buildDomainColors(report, canonicalDomains)

  if (report.summary_md) appendSummary(report.summary_md)
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
  //
  // Identity: when the gate response vends a posting token (a Semfora
  // GitHub App installation token minted server-side, scoped to this one
  // repo with pull_requests:write), comments/reviews post as semfora[bot].
  // Otherwise we fall back to the workflow token, which GitHub always
  // renders as github-actions[bot] — that identity cannot be renamed.
  const reviewers = reviewerConfig()
  const semforaToken =
    typeof settled.githubToken === "string" ? settled.githubToken : ""
  if (semforaToken) mask(semforaToken)
  const token =
    semforaToken || input("github-token") || process.env.GITHUB_TOKEN || ""
  if (semforaToken) {
    console.log("PR comments and reviews will post as semfora[bot].")
  }
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

  // require-reason: a failing gate stays red until a qualifying PR comment
  // mentions @semfora with the reason for the change.
  const requireReason = (input("require-reason") || "false").toLowerCase() === "true"
  let reasonInfo = null
  if (requireReason && report.verdict === "fail") {
    if (!canUsePr) {
      warn(
        "Semfora: require-reason is set but this is not a pull request run " +
          "(or no github-token is available) — skipped.",
      )
    } else {
      try {
        reasonInfo = await findReasonComment(token, repoSlug, pr)
      } catch (e) {
        warn(`Semfora reason lookup failed: ${e.message}`)
      }
    }
  }

  const waiver = resolveWaiver({
    verdict: report.verdict,
    approvalMode: reviewers?.approvalMode ?? "off",
    requireReason,
    approvedBy: waivedBy,
    reason: reasonInfo,
  })

  // Persist the accepted reason with what it justifies — denied domains and
  // the measured regression. Best-effort; upserted by runId server-side.
  if (reasonInfo) {
    await postReason(apiUrl, key, {
      runId: enqueued.runId,
      reason: reasonInfo.reason.slice(0, 2000),
      author: reasonInfo.author,
      commentUrl: reasonInfo.url || undefined,
      headSha: headSha || undefined,
      domains: deniedDomains(report),
      couplingNet: report.coupling_delta?.net_change ?? 0,
      complexityDelta: complexityDeltaOf(report),
    })
  }

  if (canUsePr) {
    // One gate review: the deny verdict (Changes Requested) and the inline
    // line comments ride a single review; dismissed on pass/waive.
    const lineComments = (input("line-comments") || "true").toLowerCase() !== "false"
    const requestChanges = (input("request-changes") || "true").toLowerCase() !== "false"
    if (lineComments || requestChanges) {
      try {
        await syncGateReview(token, repoSlug, pr, report, {
          denied: requestChanges && report.verdict === "fail" && !waiver.waived,
          domains: deniedDomains(report),
          lineComments,
        })
      } catch (e) {
        warn(`Semfora gate review failed: ${e.message}`)
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
            commentBody(report, repoSlug, pr.head?.sha, waiver, approvalHint, {
              domainColors,
              repoVital,
            }),
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
  setOutput("waived", waiver.waived ? "true" : "false")
  setOutput("denied-domains", deniedDomains(report).join(","))
  setOutput(
    "domains-touched",
    (report.groups_touched ?? []).map((g) => g.name).join(","),
  )
  // Outputs are single-line: collapse whitespace and cap the reason.
  setOutput(
    "reason",
    reasonInfo ? reasonInfo.reason.replace(/\s+/g, " ").slice(0, 500) : "",
  )
  setOutput("reason-author", reasonInfo ? reasonInfo.author : "")

  if (report.verdict === "fail") {
    if (waiver.waived) {
      const via = [
        waiver.approvedBy ? `@${waiver.approvedBy}'s approval` : "",
        waiver.reason ? `@${waiver.reason.author}'s reason` : "",
      ]
        .filter(Boolean)
        .join(" and ")
      appendSummary(
        `> ✅ **Waived** — ${report.errors} policy error(s) waived by ${via}.`,
      )
      notice(`Semfora gate: ${report.errors} policy error(s) waived by ${via}.`)
    } else {
      const approvalUnblock =
        reviewers?.approvalMode === "admin"
          ? " An approval of the current head commit from a repo admin waives this failure — the check re-runs on review via the pull_request_review trigger."
          : reviewers?.approvalMode === "reviewers"
            ? ` An approval of the current head commit from one of the required reviewers (${[
                ...reviewers.users,
                ...reviewers.teams.map((t) => `team ${t}`),
              ].join(", ")}) waives this failure — the check re-runs on review via the pull_request_review trigger.`
            : ""
      const reasonUnblock =
        requireReason && !reasonInfo
          ? ' A PR comment "@semfora <why this change is needed>" (PR author' +
            " or a repo collaborator) unblocks it — the comment re-runs the" +
            " gate via the issue_comment trigger and the reason is recorded" +
            " on semfora.ai."
          : ""
      fail(
        `Semfora gate failed: ${report.errors} policy error(s), ` +
          `${report.warnings} warning(s). See the step summary for details.${approvalUnblock}${reasonUnblock}`,
      )
    }
  }
  console.log(
    `Semfora gate passed (${report.warnings ?? 0} warnings, ` +
      `${report.files_changed ?? 0} files changed).`,
  )
}

if (require.main === module) {
  main().catch((e) => fail(e.message))
}

// Pure helpers exported for test.js only — the Actions runtime always enters
// through main() above (`runs.main: index.js`), so requiring this file in a
// test never talks to the network.
module.exports = {
  domainHue,
  hueToHex,
  domainFallbackColor,
  canonicalDomainColors,
  domainColorFor,
  buildDomainColors,
  toReport,
  deniedDomains,
  domainsSection,
  qualitySection,
  commentBody,
  parseReason,
  qualifiedCommenter,
  resolveWaiver,
  workflowPathFromRef,
  complexityDeltaOf,
}
