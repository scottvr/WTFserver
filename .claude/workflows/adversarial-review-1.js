export const meta = {
  name: 'adversarial-review',
  description: 'Multi-dimension review of the whatami first build with adversarial verification',
  phases: [
    { title: 'Review', detail: 'six independent review dimensions' },
    { title: 'Verify', detail: 'three refuters per deduped finding' },
  ],
}

const REPO = '/Users/bundle-tron9k/wtfserver'
const COMMON = `
You are reviewing the WTFServer / whatami first build at ${REPO}.
READ-ONLY REVIEW: do not edit any file. You may run
\`cd ${REPO} && .venv/bin/python -m pytest ...\` and ad-hoc
\`.venv/bin/python -c ...\` probes to confirm suspicions empirically.
Context: CLAUDE.md is binding engineering policy; docs/dev/CONTRACTS.md is the
binding interface contract; docs/WTFServer_First_Build.md is the scope.
Source in src/wtfserver/, tests in tests/. There is also a synthetic smoke
bundle you may analyze:
.venv/bin/python -m wtfserver.cli analyze /private/tmp/claude-502/-Users-bundle-tron9k-wtfserver/94aaa788-9f6a-48d9-b833-9f32e214fb05/scratchpad/smoke-bundle

Report ONLY findings that matter: real bugs, contract violations, invariant
violations, or over-inference risks — not style nits, not "could be nicer",
not speculative hardening. Every finding needs concrete evidence (code path,
failing input, or executed probe). Prefer fewer, verified findings over many
speculative ones. severity: high = wrong results/crash on plausible input or
invariant violation; medium = incorrect edge behavior or misleading output;
low = minor but real defect.
`

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['title', 'file', 'severity', 'category', 'description', 'evidence'],
        properties: {
          title: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          category: { type: 'string' },
          description: { type: 'string' },
          evidence: { type: 'string' },
          suggested_fix: { type: 'string' },
        },
      },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  required: ['refuted', 'reasoning'],
  properties: {
    refuted: { type: 'boolean' },
    reasoning: { type: 'string' },
    corrected_severity: { type: 'string', enum: ['high', 'medium', 'low'] },
  },
}

const DIMENSIONS = [
  {
    key: 'invariants',
    prompt: `${COMMON}
DIMENSION: Architectural invariants (CLAUDE.md).
Hunt for: Windows vocabulary or Windows-specific reasoning inside analyzers/,
report/, model.py, analysis.py (event IDs, EVTX, SCM semantics, DOMAIN\\user
PARSING — values passing through is fine, logic keyed on Windows syntax is
not; drive-letter assumptions); role/host inference living inside collectors;
collection state leaking into analysis; anything that would force a Linux
collector to lie about its data to fit the model; nondeterministic-first or
opaque scoring; external-system dependencies. Also check the evidence-class
discipline: findings labeled observed that are actually inferred, configured
items labeled observed, unknown collapsed into absence.`,
  },
  {
    key: 'bugs-collectors',
    prompt: `${COMMON}
DIMENSION: Correctness of collectors (src/wtfserver/collectors/).
Hunt for real defects: PS payload parsing (single-object vs array collapse,
null vs missing fields, non-string types where str expected), timestamp
parsing (ISO with 7-digit fractions, timezone offsets, /Date()/ leakage),
since-window filtering errors (off-by-one, naive/aware comparison crashes),
path/quote extraction bugs in services, error handling that swallows or
mislabels failures, raw_reference correctness, observation field misuse
(wrong category/action/attribute names vs CONTRACTS.md section 2). Probe
empirically with FakePowerShell-style payloads where useful.`,
  },
  {
    key: 'bugs-analyzers',
    prompt: `${COMMON}
DIMENSION: Correctness of analyzers (src/wtfserver/analyzers/) and
analysis.py. Hunt for real defects: division by zero / empty-sequence
median/statistics crashes, naive vs aware datetime comparison crashes,
threshold off-by-ones vs CONTRACTS.md section 4, cadence misclassification
(construct adversarial gap sequences), episode clustering errors (Jaccard
math, window boundaries, anchor exclusion), wrong evidence_class/confidence
vs contract, supporting_observations cap bookkeeping, findings whose details
violate the contracted schema (report depends on exact keys), crashes on
observations with missing/None fields or malformed attributes (analyzers
must never assume attribute presence). Probe empirically: build small
observation sets with tests/helpers.make_obs and run analyzers directly.`,
  },
  {
    key: 'over-inference',
    prompt: `${COMMON}
DIMENSION: Over-inference and epistemic discipline. Your job is to construct
counterexample hosts that make whatami claim things the evidence does not
support, and to find claims phrased as certainties. Check: negative-evidence
phrasing everywhere (must be window-scoped, never "this is not / nobody
uses"); role rules firing on noise (e.g. does a plain domain-joined idle
server get roles from routine Windows maintenance tasks like
\\\\Microsoft\\\\Windows\\\\... scheduled tasks — should built-in Windows
maintenance recurrence really yield "batch/scheduled processing host"?);
db_client firing on incidental connections; admin_host/quiet rules
misclassifying; confidence levels higher than the contract allows; episode
findings implying causality. Build probe bundles with make_obs +
build_ctx and run the analyzer chain (see tests for patterns). Report each
unsupported claim as a finding with the probe as evidence.`,
  },
  {
    key: 'powershell',
    prompt: `${COMMON}
DIMENSION: PowerShell script validity. The PS snippets in
src/wtfserver/collectors/windows/*.py cannot be executed in this environment,
so review them statically with expert knowledge of Windows PowerShell 5.1 on
Server 2016+ (the target). Hunt for: syntax errors (quoting/escaping after
Python string interpolation — reconstruct the exact final script text for
representative inputs and check it parses as PS), 5.1-vs-7 incompatibilities
(ternary operators, ?? operator, ConvertTo-Json depth/behavior differences,
Get-WinEvent quirks), datetime serialization that would still emit
/Date(...)/ or local time, properties that do not exist on the queried
objects (Win32_Service, Win32_Process, Get-NetTCPConnection,
Get-ScheduledTask, Get-WinEvent -ListLog), pipelines that break on
single-result collapse before reaching Python, missing -ErrorAction where a
single bad item would kill a whole channel/query, injection risks where
Python interpolates channel names or options into script text (quote
escaping for names containing ' or $), and performance landmines (rendering
Message for 25k events per channel is expected and accepted; unbounded
enumerations are not). Also check the Python-side subprocess invocation in
powershell.py for encoding and argument handling on Windows.`,
  },
  {
    key: 'determinism-integration',
    prompt: `${COMMON}
DIMENSION: Determinism and integration. Empirically verify: analyzing the
smoke bundle twice (fresh processes, different PYTHONHASHSEED env values)
produces byte-identical text and JSON output — actually run this. Check CLI
paths: analyze with --json to file and stdout, missing bundle, directory vs
zip bundle, malformed manifest. Check run_collection error paths (collector
raising, writer.abort). Check bundle round-trip with unusual observations
(unicode, huge attributes, None port). Check analyzer registry order matches
CONTRACTS.md section 8 and that roles really sees all prior findings. Check
pyproject entry point works (.venv/bin/whatami --version). Report only real
defects found, with the probe commands as evidence.`,
  },
]

phase('Review')
const reviews = await parallel(DIMENSIONS.map(d => () =>
  agent(d.prompt, { label: `review:${d.key}`, phase: 'Review', schema: FINDINGS_SCHEMA })
))

// Dedup across dimensions before paying for verification: same file + similar title.
const all = []
reviews.filter(Boolean).forEach((r, di) => {
  for (const f of r.findings || []) {
    all.push({ ...f, dimension: DIMENSIONS[di] ? DIMENSIONS[di].key : 'unknown' })
  }
})
const seen = new Map()
for (const f of all) {
  const key = `${f.file}::${(f.title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').split(' ').slice(0, 6).join(' ')}`
  if (!seen.has(key)) seen.set(key, f)
  else seen.get(key).dupes = (seen.get(key).dupes || 0) + 1
}
const deduped = [...seen.values()]
log(`${all.length} raw findings -> ${deduped.length} after dedup`)

phase('Verify')
const verified = await parallel(deduped.map((f, i) => () =>
  parallel(['correctness', 'contract-fidelity', 'reproduction'].map(lens => () =>
    agent(`${COMMON}
You are an adversarial verifier using the ${lens} lens. A reviewer claims the
following defect in the whatami codebase. Your default position is REFUTED —
only accept it if you can independently confirm it against the actual code
(and, where feasible, an executed probe). Read the cited file yourself.
If the claim is real but the severity is wrong, say so via corrected_severity.

CLAIM:
title: ${f.title}
file: ${f.file}${f.line ? ` line ~${f.line}` : ''}
severity: ${f.severity}
category: ${f.category}
description: ${f.description}
evidence given: ${f.evidence}
${f.suggested_fix ? `suggested fix: ${f.suggested_fix}` : ''}

Set refuted=false ONLY with concrete confirmation. Style opinions, working-
as-contracted behavior, and unreproducible claims are refuted=true.`,
      { label: `verify:${i}:${lens}`, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' })
  )).then(votes => {
    const good = votes.filter(Boolean)
    const accepts = good.filter(v => !v.refuted).length
    const sev = good.map(v => v.corrected_severity).filter(Boolean)
    return {
      ...f,
      votes: good.length,
      accepts,
      confirmed: accepts >= 2,
      severity_final: sev.length ? sev.sort()[0] : f.severity,
      verifier_notes: good.map(v => (v.refuted ? 'REFUTE: ' : 'ACCEPT: ') + v.reasoning.slice(0, 300)),
    }
  })
))

const confirmed = verified.filter(Boolean).filter(v => v.confirmed)
const rejected = verified.filter(Boolean).filter(v => !v.confirmed)
log(`${confirmed.length} confirmed, ${rejected.length} refuted`)
return {
  confirmed,
  rejected: rejected.map(r => ({ title: r.title, file: r.file, accepts: r.accepts, notes: r.verifier_notes.slice(0, 1) })),
}
