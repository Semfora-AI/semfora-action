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
//      verified download cached in the tool cache.
//   3. Run `semfora-engine ci` on the PR diff. The engine runs entirely on
//      this runner — source code never leaves it. Exit 10 = policy fail.
//   4. Project the report: step summary (markdown), inline annotations
//      (::error/::warning file=), and action outputs.
// ---------------------------------------------------------------------------

const { execFileSync, execFile } = require("node:child_process")
const { createHash } = require("node:crypto")
const fs = require("node:fs")
const path = require("node:path")

// --- tiny Actions runtime helpers ------------------------------------------

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

// --- 1. license verification ------------------------------------------------

async function verifyKey(apiUrl, key) {
  let res
  try {
    res = await fetch(`${apiUrl.replace(/\/$/, "")}/api/action/verify`, {
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

// --- 2. engine resolution ----------------------------------------------------

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
  const cacheRoot = process.env.RUNNER_TOOL_CACHE || fs.mkdtempSync("/tmp/semfora-")
  const dir = path.join(cacheRoot, "semfora-engine", verified.engineVersion)
  const bin = path.join(dir, "semfora-engine")
  if (!fs.existsSync(bin)) {
    fs.mkdirSync(dir, { recursive: true })
    const res = await fetch(verified.downloadUrl)
    if (!res.ok) fail(`Engine download failed (${res.status}).`)
    const bytes = Buffer.from(await res.arrayBuffer())
    if (verified.sha256) {
      const digest = createHash("sha256").update(bytes).digest("hex")
      if (digest !== verified.sha256) {
        fail("Engine binary checksum mismatch — refusing to run it.")
      }
    }
    fs.writeFileSync(bin, bytes, { mode: 0o755 })
  }
  return bin
}

// --- 3 + 4. run the gate and project the report ------------------------------

function prBaseShaFromEvent() {
  const eventPath = process.env.GITHUB_EVENT_PATH
  if (!eventPath || !fs.existsSync(eventPath)) return ""
  try {
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"))
    return event.pull_request?.base?.sha ?? ""
  } catch {
    return ""
  }
}

async function main() {
  const key = input("semfora-key")
  if (!key) fail("The semfora-key input is required.")
  const apiUrl = input("api-url") || "https://semfora.ai"
  const base = input("base") || prBaseShaFromEvent()
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

  setOutput("verdict", report.verdict ?? "pass")
  setOutput("errors", report.errors ?? 0)
  setOutput("warnings", report.warnings ?? 0)

  if (report.verdict === "fail") {
    fail(
      `Semfora gate failed: ${report.errors} policy error(s), ` +
        `${report.warnings} warning(s). See the step summary for details.`,
    )
  }
  console.log(
    `Semfora gate passed (${report.warnings ?? 0} warnings, ` +
      `${report.files_changed ?? 0} files changed).`,
  )
}

main().catch((e) => fail(e.message))
