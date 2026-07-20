// Tests for the pure helpers in index.js (node --test). Requiring index.js
// must never talk to the network: main() only runs under require.main.
//
// The domain-color cases mirror semfora-web's domain-chip tests
// (src/components/sentry/diagnosis-text.test.ts) — if one side changes the
// registry semantics, the same fixture must fail on the other.

const test = require("node:test")
const assert = require("node:assert/strict")

const {
  parseReason,
  qualifiedCommenter,
  resolveWaiver,
  workflowPathFromRef,
  complexityDeltaOf,
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
} = require("./index.js")

test("golden-angle hues anchored at the brand emerald", () => {
  assert.equal(domainHue(0), 166)
  assert.ok(Math.abs(domainHue(1) - 303.508) < 1e-9)
  // hundreds of domains stay distinct
  const hues = new Set(
    Array.from({ length: 300 }, (_, i) => domainHue(i).toFixed(3)),
  )
  assert.equal(hues.size, 300)
})

test("hueToHex is the web's oklch(0.63 0.11 h) band in sRGB", () => {
  // Pinned conversions — recompute only if the web changes its accent band.
  assert.equal(hueToHex(166), "#379e7a") // brand-adjacent emerald
  assert.equal(hueToHex(0), "#bf6b86")
  for (let h = 0; h < 360; h += 15) {
    assert.match(hueToHex(h), /^#[0-9a-f]{6}$/)
  }
})

test("canonical registry: unique colors for many domains, deterministic", () => {
  const names = Array.from({ length: 120 }, (_, i) => `domain-${i}`)
  const colors = canonicalDomainColors(names)
  const values = names.map((n) => domainColorFor(n, colors))
  assert.equal(new Set(values).size, names.length)
  const again = canonicalDomainColors(names)
  assert.equal(
    domainColorFor("domain-7", again),
    domainColorFor("domain-7", colors),
  )
})

test("fuzzy alias adopts the canonical color; unknowns fall back to hash", () => {
  const colors = canonicalDomainColors(["billing", "analysis"])
  assert.equal(
    domainColorFor("billing errors", colors),
    domainColorFor("billing", colors),
  )
  assert.equal(domainColorFor("mystery", colors), domainFallbackColor("mystery"))
})

test("extras extend the sequence without stealing group colors", () => {
  const colors = canonicalDomainColors(["billing"], ["ingest", "billing errors"])
  assert.equal(
    domainColorFor("billing errors", colors),
    domainColorFor("billing", colors),
  )
  assert.notEqual(
    domainColorFor("ingest", colors),
    domainColorFor("billing", colors),
  )
})

const sampleCi = {
  verdict: "fail",
  gateActive: true,
  errors: 1,
  warnings: 1,
  ruleHits: [
    {
      rule: "protected",
      severity: "error",
      symbol: "chargeCard",
      module: "src.billing",
      file: "src/billing/charge.ts",
      line: 42,
      groups: ["payment"],
      message: "Edit to protected domain payment",
    },
    {
      rule: "complexity",
      severity: "warn",
      symbol: "reconcile",
      module: "src.billing",
      file: "src/billing/reconcile.ts",
      line: 10,
      groups: ["payment"],
      message: "Complexity over budget",
      evidence: { cc: 34, cc_before: 12 },
    },
  ],
  ruleHitsTotal: 2,
  filesChanged: 5,
  symbolsChanged: 9,
  groupsTouched: [
    { name: "payment", symbolsChanged: 6 },
    { name: "auth", symbolsChanged: 3 },
  ],
  couplingDelta: {
    newEdges: 2,
    removedEdges: 1,
    netChange: 4,
    pairs: [{ from: "src.billing", to: "src.auth", before: 0, after: 3 }],
  },
}

test("toReport carries domains touched and the full coupling delta", () => {
  const report = toReport(sampleCi)
  assert.deepEqual(report.groups_touched, [
    { name: "payment", symbols_changed: 6 },
    { name: "auth", symbols_changed: 3 },
  ])
  assert.equal(report.coupling_delta.removed_edges, 1)
  assert.equal(report.coupling_delta.net_change, 4)
  assert.deepEqual(deniedDomains(report), ["payment"])
})

test("toReport tolerates missing/garbage groupsTouched", () => {
  assert.deepEqual(toReport({}).groups_touched, [])
  assert.deepEqual(
    toReport({ groupsTouched: [{ nope: 1 }, null, { name: "x" }] }).groups_touched,
    [{ name: "x", symbols_changed: 0 }],
  )
})

test("domainsSection renders one colored chip per touched domain", () => {
  const report = toReport(sampleCi)
  const colors = buildDomainColors(report, ["payment", "auth", "ingest"])
  const section = domainsSection(report, colors)
  assert.match(section, /#### Domains touched/)
  assert.match(section, /payment · 6 symbols/)
  assert.match(section, /auth · 3 symbols/)
  // fills carry the registry colors — same hues the dashboard assigns
  assert.ok(section.includes(`fill:${domainColorFor("payment", colors)}`))
  assert.ok(section.includes(`fill:${domainColorFor("auth", colors)}`))
  assert.equal(domainsSection(toReport({}), colors), "")
})

test("domainsSection caps at 12 chips and says how many were dropped", () => {
  const many = toReport({
    groupsTouched: Array.from({ length: 15 }, (_, i) => ({
      name: `d${i}`,
      symbolsChanged: 1,
    })),
  })
  const section = domainsSection(many, canonicalDomainColors([]))
  assert.equal((section.match(/classDef/g) || []).length, 12)
  assert.match(section, /and 3 more domain/)
})

test("qualitySection reports coupling, complexity, and the vital score", () => {
  const report = toReport(sampleCi)
  const section = qualitySection(report, { svs: 78.4, grade: "B+" })
  assert.match(section, /Cross-module coupling \| ▲ \+4 ref/)
  assert.match(section, /Cognitive complexity \| ▲ \+22 across 1 symbol/)
  assert.match(section, /Codebase Vital Score \| 78 \(B\+\)/)
  // no movement, no vital → no section
  assert.equal(qualitySection(toReport({}), null), "")
})

test("parseReason: null without a mention, empty for a bare tag, text otherwise", () => {
  assert.equal(parseReason("just a normal comment"), null)
  assert.equal(parseReason("@semfora"), "")
  assert.equal(parseReason("@semfora ok"), "")
  assert.equal(
    parseReason("@semfora hotfix for the billing outage, incident INC-42"),
    "hotfix for the billing outage, incident INC-42",
  )
  // mention anywhere in the body counts; case-insensitive; mention stripped
  assert.equal(
    parseReason("This migrates the ledger schema. @Semfora approved in RFC-7"),
    "This migrates the ledger schema. approved in RFC-7",
  )
  // @semforaXYZ is a different user, not a mention
  assert.equal(parseReason("@semforabot do things please and thanks"), null)
})

test("qualifiedCommenter: PR author and collaborators only, never bots", () => {
  const pr = { user: { login: "outside-dev" } }
  const author = { user: { login: "outside-dev" }, author_association: "NONE" }
  const member = { user: { login: "teammate" }, author_association: "MEMBER" }
  const stranger = { user: { login: "drive-by" }, author_association: "NONE" }
  const bot = { user: { login: "some-bot", type: "Bot" }, author_association: "MEMBER" }
  assert.equal(qualifiedCommenter(author, pr), true)
  assert.equal(qualifiedCommenter(member, pr), true)
  assert.equal(qualifiedCommenter(stranger, pr), false)
  assert.equal(qualifiedCommenter(bot, pr), false)
})

test("resolveWaiver: every configured waiver must hold", () => {
  const failCase = (over) =>
    resolveWaiver({
      verdict: "fail",
      approvalMode: "off",
      requireReason: false,
      approvedBy: null,
      reason: null,
      ...over,
    })
  // nothing configured → a failure is a failure
  assert.equal(failCase({}).waived, false)
  // reason alone configured and provided → waived
  const reason = { reason: "because the outage", author: "dev" }
  assert.equal(failCase({ requireReason: true, reason }).waived, true)
  assert.deepEqual(failCase({ requireReason: true }).missing, ["reason"])
  // approval alone
  assert.equal(failCase({ approvalMode: "admin", approvedBy: "boss" }).waived, true)
  // both configured → both required
  assert.equal(
    failCase({ approvalMode: "admin", requireReason: true, reason }).waived,
    false,
  )
  assert.equal(
    failCase({
      approvalMode: "admin",
      approvedBy: "boss",
      requireReason: true,
      reason,
    }).waived,
    true,
  )
  // a passing verdict never reports waived
  assert.equal(
    resolveWaiver({
      verdict: "pass",
      approvalMode: "off",
      requireReason: true,
      approvedBy: null,
      reason,
    }).waived,
    false,
  )
})

test("workflowPathFromRef strips owner/repo and the ref suffix", () => {
  assert.equal(
    workflowPathFromRef("acme/shop/.github/workflows/gate.yml@refs/heads/main"),
    ".github/workflows/gate.yml",
  )
  assert.equal(workflowPathFromRef(""), "")
  assert.equal(workflowPathFromRef(undefined), "")
})

test("complexityDeltaOf sums cc increases across complexity hits", () => {
  assert.equal(complexityDeltaOf(toReport(sampleCi)), 22)
  assert.equal(complexityDeltaOf(toReport({})), 0)
})

test("commentBody: reason-required callout and reason-waived status", () => {
  const report = toReport(sampleCi)
  const needsReason = commentBody(report, "acme/shop", "abc123", {
    waived: false,
    needsReason: true,
    reason: null,
    missing: ["reason"],
  }, "")
  assert.match(needsReason, /Reason required/)
  assert.match(needsReason, /@semfora <why this change is needed>/)

  const waived = commentBody(report, "acme/shop", "abc123", {
    waived: true,
    needsReason: true,
    reason: { reason: "the outage", author: "outside-dev" },
    approvedBy: null,
    missing: [],
  }, "")
  assert.match(waived, /waived \(reason from @outside-dev\)/)
  assert.doesNotMatch(waived, /Reason required/)
  assert.doesNotMatch(waived, /Denied by policy/)
})

test("commentBody includes the new sections and stays marked", () => {
  const report = toReport(sampleCi)
  const domainColors = buildDomainColors(report, ["payment", "auth"])
  const body = commentBody(report, "acme/shop", "abc123", null, "", {
    domainColors,
    repoVital: { svs: 78.4, grade: "B+" },
  })
  assert.match(body, /<!-- semfora-gate-comment -->/)
  assert.match(body, /#### Quality impact/)
  assert.match(body, /#### Domains touched/)
  assert.match(body, /#### Findings/)
  // still renders without the vended extras (older servers)
  const bare = commentBody(report, "acme/shop", "abc123", null, "")
  assert.match(bare, /#### Domains touched/)
  assert.doesNotMatch(bare, /Vital Score/)
})
