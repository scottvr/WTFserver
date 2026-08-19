export const meta = {
  name: 'implement-first-build',
  description: 'Parallel implementation of whatami collectors, analyzers, and reports per CONTRACTS.md',
  phases: [
    { title: 'Implement', detail: 'nine agents, disjoint file ownership, each with passing tests' },
  ],
}

const REPO = '/Users/bundle-tron9k/wtfserver'
const COMMON = `
You are implementing part of the WTFServer / whatami first build.

Repository: ${REPO}
Python: ${REPO}/.venv/bin/python (package installed editable; run tests with
\`cd ${REPO} && .venv/bin/python -m pytest tests/<your test files> -q\`).

MANDATORY reading before writing any code:
1. ${REPO}/CLAUDE.md  (engineering policy — binding)
2. ${REPO}/docs/dev/CONTRACTS.md  (exact interface contracts — binding)
3. The core modules relevant to you: src/wtfserver/model.py,
   src/wtfserver/collectors/base.py, src/wtfserver/analyzers/base.py,
   src/wtfserver/collectors/windows/powershell.py, tests/helpers.py.

HARD RULES:
- You may create/edit ONLY the files listed under "YOUR FILES". Never touch
  core modules, registries (__init__.py files), other agents' modules, or
  tests/helpers.py. Other agents are working in the same repo concurrently.
- Python stdlib only in runtime code. pytest only in tests.
- Follow CONTRACTS.md exactly: category names, attribute keys, finding types,
  details schemas, thresholds, caps, module/class names, and the module-level
  ANALYZER = ... / COLLECTOR = ... instance.
- Deterministic behavior: no wall-clock reads in analyzers, stable sort
  orders, count-desc-then-name-asc tie-breaking.
- Evidence discipline: correct evidence_class on every finding; negative
  statements always scoped to the observation window; supporting_observations
  capped at 50 with supporting_capped/supporting_total in details.
- Write focused tests including counterexamples (rule must NOT fire) and at
  least one malformed/missing-data case. Run them until they pass.
- Readable boring code. Comments only for non-obvious constraints.

If the contract is ambiguous or contradictory for your task, make the most
conservative choice consistent with CLAUDE.md, implement it, and report the
ambiguity in contract_issues — do not redesign shared interfaces.

Return (as structured output): the files you created, whether your tests pass,
how many tests, any contract issues/ambiguities, and short notes for the
integrator (anything they must know when wiring registries).
`

const RESULT_SCHEMA = {
  type: 'object',
  required: ['files', 'tests_passed', 'test_count', 'contract_issues', 'integrator_notes'],
  properties: {
    files: { type: 'array', items: { type: 'string' } },
    tests_passed: { type: 'boolean' },
    test_count: { type: 'integer' },
    contract_issues: { type: 'array', items: { type: 'string' } },
    integrator_notes: { type: 'string' },
  },
}

const TASKS = [
  {
    label: 'collector:eventlog',
    prompt: `${COMMON}
TASK: Implement the Windows event log collector — the most important collector.

YOUR FILES:
- src/wtfserver/collectors/windows/eventlog.py  (class EventLogCollector,
  name "eventlog", plus module-level COLLECTOR = EventLogCollector())
- tests/test_collector_eventlog.py

Implement per CONTRACTS.md §3 (eventlog specifics) and §2 (evidence_channel,
event categories, and the full event-ID normalization map). Key points:
- Enumerate ALL channels via ctx.runner; emit one evidence_channel observation
  per channel (even disabled/empty ones), with the exact attribute keys.
- Collect history only from enabled channels with record_count > 0, newest
  events first up to ctx.options.get("max_events_per_channel", 25000);
  set truncated correctly (truncated means the cap cut off events that were
  inside the requested window). Respect ctx.since = None meaning max history.
- Per-channel oldest/newest via two -MaxEvents 1 queries; tolerate failures.
- PS snippets must emit JSONL (one compact JSON object per line) with fields
  t, id, provider, channel, level, record_id, props (stringified property
  values, cap 20), msg (300 chars). All datetimes ISO UTC via calculated
  properties. Design the PS here; tests exercise the Python side via
  FakePowerShell from tests/helpers.py (payloads = parsed JSON, i.e. lists of
  dicts for run_jsonl).
- Normalize the mapped event IDs exactly per the contract table (Security
  4624/4625/4634/4647/4688/4689; SCM 7036/7045; 6005/6006/6008; TaskScheduler
  100/101/102/103/106/110/111/129/200/201; TerminalServices LSM 21/23/24/25).
  Everything else becomes category "event". Every historical observation
  carries channel/provider/event_id/level attributes and a raw_reference to
  the channel's raw JSONL file (write raw via ctx.add_raw).
- A channel that fails to read yields an evidence_channel observation with
  error set plus a CollectorError; never an exception. Malformed individual
  event rows are skipped, counted in stats.
- Filter events older than ctx.since client-side too (defense in depth).
Tests must cover: normalization of each mapped family (at least 4624 logon
kinds incl. remote_host filtering of '-' and loopback, 4688, 7036
running/stopped/localized-unknown, TaskScheduler 100/201, TS-LSM 21),
unmapped event fallback, disabled channel inventory, per-channel read failure,
malformed event rows, truncation flagging, and since-filtering.`,
  },
  {
    label: 'collector:services-tasks-software',
    prompt: `${COMMON}
TASK: Implement three Windows state collectors.

YOUR FILES:
- src/wtfserver/collectors/windows/services.py  (ServicesCollector, name "services", COLLECTOR = ...)
- src/wtfserver/collectors/windows/scheduled_tasks.py  (ScheduledTasksCollector, name "scheduled_tasks", COLLECTOR = ...)
- src/wtfserver/collectors/windows/software.py  (SoftwareCollector, name "software", COLLECTOR = ...)
- tests/test_collector_services.py
- tests/test_collector_scheduled_tasks.py
- tests/test_collector_software.py

Per CONTRACTS.md §2 (service_state, scheduled_task_state, installed_role,
installed_software) and §3. Notes:
- services: Get-CimInstance Win32_Service. Extract the bare executable path
  from PathName (handle quoted paths with arguments, unquoted paths with
  arguments like "C:\\Windows\\system32\\svchost.exe -k netsvcs", and null).
  Keep raw in attributes.raw_path. Lowercase state/start_mode ("Auto"->"auto").
- scheduled_tasks: Get-ScheduledTask joined with Get-ScheduledTaskInfo in one
  PS script building explicit objects (task path+name, State, principal
  UserId, actions Execute/Arguments, trigger CIM class names + StartBoundary
  + Repetition.Interval, LastRunTime/NextRunTime/LastTaskResult/
  NumberOfMissedRuns, Hidden). Map trigger CIM classes to the short type
  strings (MSFT_TaskDailyTrigger->daily, TimeTrigger->time, BootTrigger->boot,
  LogonTrigger->logon, repetition interval present->interval, else other).
  Convert PS ISO8601 durations like PT15M in Repetition.Interval to seconds in
  attributes if easy, else keep raw string (document which you chose in
  integrator_notes). LastRunTime of year 1899 or null means never-ran -> null.
- software: installed roles via Get-WindowsFeature (Installed only; tolerate
  the cmdlet being absent on client SKUs -> CollectorError, continue);
  installed software via registry uninstall keys (both 64-bit and WOW6432Node
  hives) through one PS script; skip entries without DisplayName; parse
  InstallDate yyyyMMdd when present.
- Each collector writes its raw payload via ctx.add_raw and sets
  raw_reference like "raw/services.json#<index>".
Tests: realistic canned payloads via FakePowerShell incl. single-object (PS
ConvertTo-Json collapses one-element arrays to a bare object — handle both!),
empty results, missing fields, path-extraction edge cases, runner exceptions
becoming CollectorError not crashes.`,
  },
  {
    label: 'collector:proc-net-identity',
    prompt: `${COMMON}
TASK: Implement three Windows state collectors.

YOUR FILES:
- src/wtfserver/collectors/windows/processes.py  (ProcessesCollector, name "processes", COLLECTOR = ...)
- src/wtfserver/collectors/windows/network.py  (NetworkCollector, name "network", COLLECTOR = ...)
- src/wtfserver/collectors/windows/host_identity.py  (HostIdentityCollector, name "host_identity", COLLECTOR = ...)
- tests/test_collector_processes.py
- tests/test_collector_network.py
- tests/test_collector_host_identity.py

Per CONTRACTS.md §2 (process_state, socket_state, host_identity) and §3.
Notes:
- processes: Get-CimInstance Win32_Process with CreationDate as ISO via
  calculated property; owner via Invoke-CimMethod GetOwner per process inside
  the PS script, tolerating per-process failure (owner null). principal =
  "DOMAIN\\user" when both parts present, bare user otherwise.
- network: TCP via Get-NetTCPConnection (states Listen -> action "listening",
  Established -> "established"; ignore TimeWait/CloseWait etc. but record
  counts in stats), UDP listeners via Get-NetUDPEndpoint (action "listening",
  protocol udp). Resolve owning process name in PS via a PID->name table from
  Get-Process. Collect loopback too (analyzers filter). local/remote
  addresses as strings; ports as ints.
- host_identity: one observation. Win32_ComputerSystem (Name, Domain,
  PartOfDomain, DomainRole), Win32_OperatingSystem (Caption, Version,
  LastBootUpTime ISO), Get-NetIPAddress for interfaces (skip APIPA
  169.254.*), Get-DnsClientServerAddress for DNS servers. Map DomainRole int
  to a string: 0/2 standalone, 1/3 member, 4/5 domain_controller.
Tests: canned payloads incl. single-object collapse, missing owner, empty
UDP, IPv6 addresses, workgroup host (no domain), runner failure of one
sub-query -> partial result + CollectorError.`,
  },
  {
    label: 'analyzer:coverage-frequency',
    prompt: `${COMMON}
TASK: Implement the coverage and frequency analyzers.

YOUR FILES:
- src/wtfserver/analyzers/coverage.py  (CoverageAnalyzer, name "coverage", ANALYZER = ...)
- src/wtfserver/analyzers/frequency.py  (FrequencyAnalyzer, name "frequency", ANALYZER = ...)
- tests/test_analyzer_coverage.py
- tests/test_analyzer_frequency.py

Per CONTRACTS.md §4 (evidence_coverage, frequency_summary, limitation).
Coverage details:
- Reads evidence_channel observations + ctx.manifest collector records.
- evidence_coverage finding: exactly one, evidence_class observed, with the
  window/channels/total_span_days details exactly as specified (span_days =
  newest-oldest in days rounded to 1 decimal; covers_window = oldest <=
  resolved window start, null when window is max or oldest unknown).
- limitation findings with the specified kinds: channel_disabled only for the
  named interesting channels; retention_short when a populated channel's
  oldest record is newer than the window start; truncated; collector_error
  (from manifest collector records with errors/failed status);
  no_process_auditing when eventlog observations exist but zero
  process_activity start events came from the Security channel (check
  attributes.channel == "Security" — TaskScheduler action_start events don't
  count as process auditing); no_security_log when no evidence_channel for
  Security or it has error/zero records; no_history when there are no
  historical observations at all.
- Required categories: none (always runs — it must report even when eventlog
  collection failed entirely).
Frequency: exactly one frequency_summary finding per contract — top-N lists
with exact key names, machine-account/noise-principal filtering into
system_principals, process basename grouping with process_paths map,
"Provider:1234" event-id keys. Counts events across ALL historical categories
(event, logon, process_activity, service_activity, scheduled_activity,
system_lifecycle) for providers/event_ids; principals/services/etc. from the
relevant normalized fields across historical + state observations where
sensible per contract. supporting_observations: cap 50 (these will be huge —
use the cap fields).
Tests: verify exact detail shapes, tie-breaking determinism (equal counts ->
name asc), noise-principal filtering, empty-bundle behavior (frequency emits
finding with empty lists or skips gracefully — choose: emit with empty lists),
coverage limitations each triggered and each NOT triggered by a
counterexample.`,
  },
  {
    label: 'analyzer:recurrence-correlation',
    prompt: `${COMMON}
TASK: Implement the recurrence and correlation analyzers — the heart of the
product hypothesis ("this same little sequence happened 21 times").

YOUR FILES:
- src/wtfserver/analyzers/recurrence.py  (RecurrenceAnalyzer, name "recurrence", ANALYZER = ...)
- src/wtfserver/analyzers/correlation.py  (CorrelationAnalyzer, name "correlation", ANALYZER = ...)
- tests/test_analyzer_recurrence.py
- tests/test_analyzer_correlation.py

Per CONTRACTS.md §4 (recurring_scheduled_activity, activity_episode) —
follow the cadence classification rules and episode signature/similarity
rules exactly. Additional guidance:
- recurrence: group scheduled_activity action=="start" by scheduled_action;
  >=3 starts required. Gaps = consecutive start deltas in seconds. Median and
  MAD computed deterministically (statistics.median is fine). typical_time
  computed from start times-of-day using circular median is overkill — use
  plain median of seconds-since-midnight UTC, format HH:MM (document edge
  case near midnight in a comment; acceptable first-build simplification).
  principal/process = most common non-null among the task's start and
  action_start observations (associate action_start to the same
  scheduled_action value); failure_count from action=="failed".
  supporting_observations = the start observation IDs (cap 50).
- correlation: anchors per contract. Build per-anchor member sets from
  observations in [anchor-5s, anchor+300s] (excluding the anchor itself and
  other anchor-identical events). Member kind naming per contract; use
  process basename; remote peers as "host:port". Group anchor occurrences by
  anchor identity; within a group, cluster occurrences greedily in time order:
  an occurrence joins the first cluster whose representative (first
  occurrence) has member-kind Jaccard >= 0.6. Cluster with >=3 occurrences ->
  one activity_episode finding. typical_offset_seconds = median offset of
  that member kind across occurrences containing it; seen_in = number of
  occurrences containing it; keep members present in >=50% of occurrences,
  order by typical offset, cap 12. supporting_observations: anchor obs IDs
  plus a few member IDs, cap 50.
Tests: the canonical scenario — 21 nightly runs at 01:00 +/- 2 min of task
"\\\\Vendor\\\\NightlyExport" with svc_export logon + export.exe action_start
+ established peer db01:1433 inside the window -> exactly one recurrence
finding (cadence daily, typical_time "01:00", count 21) and one episode
finding whose typical_sequence contains the logon, process, and peer steps in
offset order. Counterexamples: 2 executions -> nothing; irregular gaps ->
cadence "irregular"; unrelated noise events inside windows do not enter
typical_sequence (below 50% presence); two different anchors don't merge.
Also: observations missing timestamps are skipped without crashing.`,
  },
  {
    label: 'analyzer:assoc-peers',
    prompt: `${COMMON}
TASK: Implement the associations and peers analyzers.

YOUR FILES:
- src/wtfserver/analyzers/associations.py  (AssociationsAnalyzer, name "associations", ANALYZER = ...)
- src/wtfserver/analyzers/peers.py  (PeersAnalyzer, name "peers", ANALYZER = ...)
- tests/test_analyzer_associations.py
- tests/test_analyzer_peers.py

Per CONTRACTS.md §4 (process_association, peer_dependency).
- associations: scan historical observations where process is non-null;
  for each, pair its basename with the same observation's scheduled_action,
  service, principal, and (remote_host:port) when present. Count pairs;
  emit one finding per pair with count >=3, sorted by count desc then
  process asc then name asc. Skip pairs where the associated name is a noise
  principal (SYSTEM etc. — same filter list as frequency contract).
  process_path = most common full path for that basename.
- peers: group per contract (current socket_state established + historical
  remote_host-bearing observations EXCLUDING category logon), filter
  loopback/unspecified/link-local (IPv4 and IPv6 — 127/8, 0.0.0.0, ::, ::1,
  169.254/16, fe80::/10), evidence current/historical/both, service_hint from
  the exact port map, processes list <=5 sorted by frequency, cap 25 findings
  with peers_omitted noted. remote_port may be null for historical
  observations lacking it — group (host, null) separately.
Tests: association threshold (3 yes, 2 no), noise-principal exclusion,
deterministic ordering with equal counts; peers: loopback filtered, hint map
correct for 1433/22/unknown port -> null, both-evidence detection, cap
behavior with 30 synthetic peers, port-null grouping.`,
  },
  {
    label: 'analyzer:interactive-configured',
    prompt: `${COMMON}
TASK: Implement the interactive-use and configured-but-unobserved analyzers.

YOUR FILES:
- src/wtfserver/analyzers/interactive.py  (InteractiveAnalyzer, name "interactive", ANALYZER = ...)
- src/wtfserver/analyzers/configured_unobserved.py  (ConfiguredUnobservedAnalyzer, name "configured_unobserved", ANALYZER = ...)
- tests/test_analyzer_interactive.py
- tests/test_analyzer_configured_unobserved.py

Per CONTRACTS.md §4 (interactive_use, configured_but_unobserved) — follow the
classification rule order and the emission conditions exactly.
- interactive: counts come from logon-category observations (action logon for
  the kind counts, action logon_failed for failed_logons). window_days from
  since..collection_end, or from observed logon span when since is max
  (document choice in a comment; use since when available else span of ALL
  historical observations). interactive_principals uses the machine-account/
  noise filter from the contract. Conclusion sentence must include counts and
  window as specified. evidence_class unknown + a clear conclusion when no
  logon observations exist ("No logon evidence available...").
- configured_unobserved: only emit item findings when historical eventlog
  evidence exists (any observation with category in the historical set whose
  source is "eventlog"); otherwise ONE limitation finding (kind no_history
  subject "configured_unobserved") explaining dormancy can't be assessed.
  Service matching: case-insensitive containment of the service name in
  service/message fields of service_activity and process_activity
  observations. Scheduled task matching by exact path against
  scheduled_activity.scheduled_action. last_run comparison against window
  start (ctx.since); when since is None (max) treat any non-null last_run as
  observed-at-some-point -> do NOT flag the task (conservative). Role
  indicator map exactly as contracted, small and literal. Cap 15 prioritized
  auto-start first then name asc; a final note about omissions when capped.
  window_days as in interactive.
Tests per contract: each emission rule + a counterexample (e.g. stopped
manual service WITH observed service_activity start must not be flagged;
running service never flagged; enabled task with recent last_run inside
window not flagged; Web-Server role WITH w3svc running + :443 listening not
flagged; no-history bundle -> single limitation, zero configured findings).`,
  },
  {
    label: 'analyzer:roles',
    prompt: `${COMMON}
TASK: Implement the role inference analyzer — the only analyzer that reads
prior findings.

YOUR FILES:
- src/wtfserver/analyzers/roles.py  (RolesAnalyzer, name "roles", ANALYZER = ...)
- tests/test_analyzer_roles.py

Per CONTRACTS.md §4 role_inference: implement EXACTLY the eight rules
(role.batch.v1, role.db_client.v1, role.transfer_client.v1, role.web_server.v1,
role.db_server.v1, role.dc.v1, role.admin_host.v1, role.quiet.v1) with the
stated conditions, confidence assignments, role strings, rule_id on each
finding, details {role, evidence_summary}, and supporting_observations copied
from the findings/observations each rule used (cap 50). Read prior findings
via ctx.findings_of_type(...); read observations for service/socket/identity
conditions. Emission order: rule order as listed, then within a rule sort by
the natural key (e.g. peer host) for determinism. evidence_class inferred.
Conclusions are single sentences naming the role and the core evidence, e.g.
"Recurring scheduled activity (\\\\Vendor\\\\NightlyExport, 21 runs, daily
cadence) indicates a batch/scheduled processing host."
In tests, construct prior findings by hand (Finding(...) with the contracted
details shapes — copy shapes from CONTRACTS.md §4) and set
ctx.prior_findings before calling analyze. Each rule needs: a firing case
with correct confidence, a threshold counterexample that must NOT fire, and
for db_client the local-DB-service suppression case (peer 1433 but local
mssql service running -> no db_client role). Also verify role.quiet.v1's
conclusion mentions the window and does not claim the host is unused, and
role.admin_host.v1 is suppressed when a batch role fired.`,
  },
  {
    label: 'report',
    prompt: `${COMMON}
TASK: Implement report rendering, text and JSON.

YOUR FILES:
- src/wtfserver/report/text.py  (render_text(result) -> str)
- src/wtfserver/report/json_out.py  (render_json(result) -> dict)
- tests/test_report_text.py
- tests/test_report_json.py

Per CONTRACTS.md §6 exactly: section order, headers, finding-ID brackets on
every rendered conclusion, omission rules, JSON keys/shape, round-trip
through json.dumps. AnalysisResult is in src/wtfserver/analysis.py (read it,
do not edit it) — you get .manifest, .findings, .observations_summary, and
.of_type(finding_type).
Guidance:
- HOST section: hostname + platform from manifest; os/domain details from the
  host_identity... note: the report only has findings + manifest +
  observations_summary — host_identity attributes are NOT findings. Solution
  within your ownership: render what the manifest has (hostname, platform,
  tool_version, collection time, requested window) and ALSO accept optional
  host details if the evidence_coverage finding or a finding of type
  "host_identity" exists. Additionally: check whether
  result.observations_summary helps. If you conclude host OS details cannot
  be rendered from findings alone, note it in contract_issues (the
  integrator may add a small host summary to AnalysisResult) and render
  hostname/platform from the manifest for now. Do not edit analysis.py.
- EVIDENCE section: from the evidence_coverage finding details: window line,
  then up to ~12 channel rows "channel: X days (N records)" sorted as given,
  plus truncation/error markers; then total span line.
- LIKELY ROLES: "role  CONFIDENCE  [f-id]" lines; when no role_inference
  findings exist print "No role inference met evidence thresholds." (exact).
- PRIMARY RECURRING ACTIVITY: each recurrence finding as a small block (task,
  count, cadence/typical_time, principal -> process); then episodes with
  their typical_sequence as indented "+Ns  category action name" lines.
- OBSERVED PEERS: "host:port  (hint)  xN  evidence  [f-id]"; handle null port.
- Sections with nothing to say are omitted EXCEPT EVIDENCE and LIMITATIONS
  (LIMITATIONS prints "None recorded." if empty — rare but possible).
- Text must be pure ASCII-safe (no box drawing), <=100 cols, 2-space indents.
- JSON: exact top-level keys from the contract; details dicts embedded with
  finding id/conclusion/confidence merged as specified.
Tests: build a representative fake AnalysisResult by hand with one finding of
every type (use the contracted details shapes), assert section presence/order,
finding-id brackets, omission of empty sections, the exact no-roles line,
JSON key completeness, and json.dumps round-trip. Also an empty-findings
result renders without crashing.`,
  },
]

phase('Implement')
const results = await parallel(TASKS.map(t => () =>
  agent(t.prompt, { label: t.label, phase: 'Implement', schema: RESULT_SCHEMA })
))

const summary = results.map((r, i) => ({ task: TASKS[i].label, result: r }))
const failed = summary.filter(s => !s.result || !s.result.tests_passed)
log(`${summary.length - failed.length}/${summary.length} implementation agents report passing tests`)
return { summary, failed: failed.map(f => f.task) }
