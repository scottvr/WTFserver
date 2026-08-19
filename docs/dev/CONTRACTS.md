# Implementation Contracts (first build)

This document is binding for everyone (human or agent) implementing collectors,
analyzers, or reports. It concretizes CLAUDE.md and
docs/WTFServer_First_Build.md into exact interfaces. If following this document
would require violating an architectural invariant in CLAUDE.md, stop and
surface the conflict — do not improvise.

Core modules (`model.py`, `bundle.py`, `timeparse.py`, `collect.py`,
`analysis.py`, `cli.py`, `collectors/base.py`, `analyzers/base.py`,
`collectors/windows/powershell.py`) are owned by the integrator. Implementation
agents MUST NOT edit them; report contract problems instead.

---

## 1. Global rules

- Runtime code uses the Python standard library only. Test-only dep: pytest.
- All timestamps are ISO 8601 UTC strings with `Z` suffix
  (`model.to_iso` / `model.parse_iso`). Never store local time.
- Analyzers never call `datetime.now()`; use `ctx.collection_end`.
- Determinism: identical bundle in → identical findings out (IDs included).
  Iterate dicts in insertion or sorted order; break count ties with name order.
- Confidence is only `HIGH` / `MEDIUM` / `LOW` (constants in `model.py`).
- Every Finding carries `evidence_class`: `configured` / `observed` /
  `inferred` / `unknown` (constants in `model.py`). Descriptive summaries of
  things that happened are `observed`; conclusions drawn from them are
  `inferred`; statements about installed-but-idle things are `configured`.
- Negative evidence phrasing: always scope to the window. Say
  "No X was observed during the N-day available history", never "X does not
  happen" / "this is not an X server".
- Windows vocabulary (event IDs, EVTX, SCM, `DOMAIN\user` parsing, drive
  letters) is allowed ONLY inside `collectors/windows/` and in observation
  `attributes` values. Analyzers and reports reason over normalized fields and
  the attribute keys defined in this document.

## 2. Observation categories and attribute keys

`Observation` fields: see `model.py`. `source` = collector name.
Categories are constants in `model.Category`. Attribute keys below are the
contract between collectors and analyzers — use these exact names.

### evidence_channel  (source: eventlog)
One per discovered log channel (all channels, even empty/disabled ones —
coverage needs them). `timestamp` = collection time.
- action: `"inventoried"`
- attributes: `channel` (str), `enabled` (bool), `record_count` (int),
  `oldest_record` (ISO str | null), `newest_record` (ISO str | null),
  `max_size_bytes` (int | null), `collected_events` (int, events actually
  collected from this channel), `truncated` (bool, true if the per-channel cap
  cut off history inside the window), `error` (str, only on read failure)

### Historical event categories (source: eventlog)
Every historical event observation, normalized or not, carries in attributes:
`channel` (str), `provider` (str), `event_id` (int), `level` (str|null).
`raw_reference` points at the raw events file (e.g. `raw/events_Security.jsonl`).

- **event** — any event not specifically normalized. action: null.
  `message` = first 300 chars of rendered message (may be null).
- **logon** — actions: `logon`, `logoff`, `logon_failed`.
  `principal` = `DOMAIN\user` as reported (value may be platform syntax; key
  is neutral). extra attributes: `logon_kind` one of `interactive`,
  `remote_interactive`, `network`, `batch`, `service`, `unlock`, `other`;
  `logon_type` (int|null, raw). `remote_host` = source address if present and
  not loopback/`-`. `process` = logon process image if present.
- **process_activity** — actions: `start`, `stop`. `process` = full image
  path as reported. attributes: `command_line` (str|null), `parent_process`
  (str|null). `principal` = subject user if present.
- **service_activity** — actions: `start`, `stop`, `installed`,
  `state_change`. `service` = service/display name as reported.
  attributes: `state` (raw string|null).
- **scheduled_activity** — actions: `start`, `complete`, `failed`,
  `registered`, `action_start`, `action_complete`, `terminated`.
  `scheduled_action` = task path (e.g. `\Vendor\NightlyExport`).
  `principal` = user context if present. `process` = action executable for
  `action_start`/`action_complete` (event 129/200/201). attributes:
  `result_code` (int|null).
- **system_lifecycle** — actions: `boot`, `shutdown`, `unexpected_shutdown`.

### Event ID normalization map (collector-internal, listed here so analyzers
know what to expect):
- Security 4624→logon/logon (logon_type prop 8, principal props 5\6 →
  `DOMAIN\user`, IpAddress prop 18→remote_host; type map 2=interactive,
  3=network, 4=batch, 5=service, 7=unlock, 10=remote_interactive, else other)
- Security 4625→logon/logon_failed; 4634,4647→logon/logoff
- Security 4688→process_activity/start (NewProcessName prop 5, CommandLine
  prop 8 if present, parent prop 13 on 2016+); 4689→process_activity/stop
- System/Service Control Manager 7036→service_activity/state_change
  (service=param1, state=param2; map English "running"→action start,
  "stopped"→action stop, anything else stays state_change)
- System 7045→service_activity/installed; 6005→system_lifecycle/boot,
  6006→shutdown, 6008→unexpected_shutdown
- Microsoft-Windows-TaskScheduler/Operational: 100→scheduled_activity/start,
  102→complete, 101,103→failed, 106→registered, 111→terminated,
  129→action_start (process=Path prop), 200→action_start (process=ActionName),
  201→action_complete (result_code prop), 110→start
- Microsoft-Windows-TerminalServices-LocalSessionManager/Operational:
  21→logon/logon (logon_kind=remote_interactive, principal=User prop,
  remote_host=Address prop unless "LOCAL"), 23→logon/logoff,
  24,25→event (keep generic, message notes disconnect/reconnect)
- Everything else → category `event`.

### Current-state categories. `timestamp` = collection time for all.

- **service_state** (source: services) — action `configured`.
  `service` = service name. `principal` = service account (as reported).
  `process` = executable path extracted from the raw command (strip quotes and
  arguments; keep full raw in attributes). attributes: `display_name`,
  `state` (lowercased, e.g. `running`/`stopped`), `start_mode` (lowercased:
  `auto`/`manual`/`disabled`), `raw_path` (full command line str|null).
- **scheduled_task_state** (source: scheduled_tasks) — action `configured`.
  `scheduled_action` = full task path (`\Folder\Name`). `principal` = task
  principal. `process` = first action executable (null if none). attributes:
  `enabled` (bool), `state` (str), `actions` (list of
  `{execute, arguments}`), `triggers` (list of `{type, start, interval}` where
  type is a short string like `daily`, `time`, `boot`, `logon`, `interval`,
  `other`), `last_run` (ISO|null), `next_run` (ISO|null),
  `last_result` (int|null), `missed_runs` (int|null), `hidden` (bool|null).
- **process_state** (source: processes) — action `running`.
  `process` = executable path or name. `principal` = owner (`DOMAIN\user`)
  when available. attributes: `pid` (int), `parent_pid` (int|null),
  `command_line` (str|null), `start_time` (ISO|null).
- **socket_state** (source: network) — actions: `listening`, `established`.
  For `established`: `remote_host` (IP string as observed), `remote_port`.
  `process` = owning process name if available. attributes: `protocol`
  (`tcp`/`udp`), `local_address`, `local_port` (int), `pid` (int|null),
  `state` (raw str). Loopback (`127.0.0.0/8`, `::1`) and unspecified remote
  endpoints are still collected; analyzers filter.
- **host_identity** (source: host_identity) — action `identity`, exactly one
  observation. attributes: `hostname`, `fqdn` (nullable), `os_name`,
  `os_version`, `domain` (nullable), `domain_role` (nullable str),
  `interfaces` (list of `{name, addresses}`), `dns_servers` (list[str]),
  `last_boot` (ISO|null).
- **installed_role** (source: software) — action `installed`. one per
  installed role/feature. attributes: `name` (e.g. `Web-Server`),
  `display_name`. `message` = display name.
- **installed_software** (source: software) — action `installed`.
  attributes: `name`, `version` (nullable), `vendor` (nullable),
  `install_date` (ISO|null). `message` = name.

## 3. Collector specs

All Windows collectors live in `collectors/windows/`, subclass
`collectors.base.Collector`, set `platforms = ("windows",)`, and reach the OS
ONLY via `ctx.runner` (PowerShell runner). Each collector:
- writes its raw payload(s) via `ctx.add_raw(name, content)` and sets
  `raw_reference` on observations,
- catches per-item failures, appends `CollectorError` to result.errors, and
  continues (fatal=True only if nothing at all could be collected),
- serializes PS datetimes with calculated properties
  `.ToUniversalTime().ToString('o')` — never rely on ConvertTo-Json defaults,
- respects `ctx.since` (None = max history) and `ctx.now`.

| collector name  | module              | categories produced                    |
|-----------------|---------------------|----------------------------------------|
| eventlog        | eventlog.py         | evidence_channel, event, logon, process_activity, service_activity, scheduled_activity, system_lifecycle |
| services        | services.py         | service_state                          |
| scheduled_tasks | scheduled_tasks.py  | scheduled_task_state                   |
| processes       | processes.py        | process_state                          |
| network         | network.py          | socket_state                           |
| host_identity   | host_identity.py    | host_identity                          |
| software        | software.py         | installed_role, installed_software     |

eventlog specifics: enumerate all channels (`Get-WinEvent -ListLog *`);
inventory every channel; collect history only from enabled channels with
`record_count > 0`, using `-FilterHashtable @{LogName=...; StartTime=...}`
(omit StartTime for max), capped at
`ctx.options.get("max_events_per_channel", 25000)` newest events per channel;
set `truncated` accordingly. Query oldest/newest per populated channel with
two `-MaxEvents 1` queries (`-Oldest` and default). Emit events as JSONL from
PS (one compact JSON per line via `ConvertTo-Json -Compress -Depth 4` inside
`ForEach-Object`) with fields: `t` (ISO time), `id`, `provider`, `channel`,
`level`, `record_id`, `props` (array of property values as strings, may be
truncated at 20 items), `msg` (message truncated to 300 chars). Store each
channel's JSONL as `raw/events_<sanitized-channel>.jsonl`. Channels that fail
to read get `error` on their evidence_channel observation and a
CollectorError, not an exception.

## 4. Finding types and details schemas

Constants in `model.FindingType`. The report renders ONLY from these — if it
isn't in `details`, the report can't show it. Cap `supporting_observations`
at 50 IDs per finding; when capped, set `details["supporting_capped"] = true`
and `details["supporting_total"] = <int>`.

### evidence_coverage (analyzer: coverage) — exactly one; evidence_class observed
details:
```
window: {requested: str, resolved: ISO|null, collection_end: ISO}
channels: [{channel, enabled, record_count, oldest, newest, span_days (float|null),
            covers_window (bool|null), collected_events, truncated, error}]
   — only channels with record_count>0 or enabled=false worth noting; sorted
     by record_count desc; cap 40 rows, details.channels_omitted = int
total_span_days: float|null   (max span across populated channels)
```
Also emits `limitation` findings (see below) for: disabled-but-interesting
channels (Security, TaskScheduler/Operational, PowerShell/Operational),
channels whose oldest record is younger than the requested window (retention
shortfall), truncated channels, collector errors from the manifest, absence of
process_activity start events (process auditing off), and Security channel
absent/unreadable.

### frequency_summary (analyzer: frequency) — exactly one; observed
details: `top_providers`, `top_event_ids`, `top_principals`, `top_services`,
`top_scheduled_actions`, `top_processes`, `top_remote_hosts`,
`top_remote_ports` — each a list of `[name, count]` pairs (name str, count
int), length ≤ ctx.options["top_n"] (default 10), sorted count desc then name
asc. `top_event_ids` entries are `"Provider:1234"`. Principals: exclude
machine accounts (names ending `$`) and well-known noise principals
(`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, with or
without domain prefix) from `top_principals` but keep a separate
`system_principals` list. Processes: use basename for grouping, keep full
path of most-common variant in `process_paths` map.

### recurring_scheduled_activity (analyzer: recurrence) — one per recurring
task; observed. Emitted when a `scheduled_action` has ≥3 `start` observations.
details:
```
scheduled_action, count (int), first (ISO), last (ISO),
cadence: "daily" | "hourly" | "interval" | "weekdays" | "irregular",
interval_seconds: float|null (median inter-start gap),
typical_time: "HH:MM"|null (median start time-of-day UTC, when cadence daily/weekdays),
jitter_seconds: float|null (median absolute deviation of gaps),
principal: str|null (most common), process: str|null (most common associated
  action executable from action_start events or task state),
failure_count: int (failed observations for same task in window)
```
cadence rules: daily = median gap within 86400±3600 s; hourly = 3600±300;
weekdays = median gap 86400±3600 with weekend gaps ~2-3 days and all starts
Mon–Fri; interval = any other stable gap (MAD < 20% of median); otherwise
irregular. Regularity is judged on gaps between consecutive starts.

### activity_episode (analyzer: correlation) — one per repeated episode
pattern; observed. Anchors: `scheduled_activity` action=start,
`service_activity` action=start, `logon` action=logon (kinds interactive /
remote_interactive / batch only). Window: anchor −5 s … +300 s (configurable
via ctx.options `correlation_before`/`correlation_after`). An episode's
signature = anchor identity (category + name field) plus the SET of member
kinds, where a member kind is `(category, action, name-field value)` using
service/scheduled_action/process-basename/remote_host:port/principal as the
name. Signatures match when anchor identity is equal and member-kind Jaccard
similarity ≥ 0.6. Emit when a signature repeats ≥3 times.
details:
```
anchor: {category, action, name},
occurrences: int, first: ISO, last: ISO,
typical_sequence: [{category, action, name, typical_offset_seconds (float),
                    seen_in: int}]   — ordered by typical offset; only members
                    appearing in ≥50% of occurrences; cap 12 steps
```
Do not emit episodes whose members are only the anchor itself.

### process_association (analyzer: associations) — one per strong
association; observed. From historical observations, associate processes
(basename) with scheduled_actions, services, principals, and remote peers
when they co-occur on the same observations (e.g. scheduled_activity
action_start carries process; logon carries principal+process). Emit when a
pair co-occurs ≥3 times.
details: `process`, `process_path` (most common full path|null),
`associated_with`: `{kind: "scheduled_action"|"service"|"principal"|"peer",
name, count}` (one finding per pair), `total_process_observations` (int).

### peer_dependency (analyzer: peers) — one per remote peer:port; observed.
Sources: socket_state established (current) and historical observations with
remote_host set (logon sources excluded — a logon's source address is not an
outbound dependency; keep those under interactive analysis). Exclude
loopback, unspecified, and link-local addresses. Group by (remote_host,
remote_port). For current sockets, remote_port present; count = distinct
observations.
details: `remote_host`, `remote_port` (int|null), `count`,
`evidence`: "current" | "historical" | "both",
`processes`: [str] (owning/associated process basenames, ≤5),
`service_hint`: str|null — well-known port label from this map only:
{22: "ssh/sftp", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
135: "msrpc", 389: "ldap", 443: "https", 445: "smb", 587: "smtp",
636: "ldaps", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
5432: "postgresql", 5985: "winrm", 5986: "winrm", 6379: "redis",
8080: "http-alt", 9389: "adws", 27017: "mongodb"}.
Sort findings by count desc. Cap at 25 peers; note omitted count in the last
finding's details (`peers_omitted`).

### interactive_use (analyzer: interactive) — exactly one; evidence_class
observed if logon evidence exists, else unknown.
details:
```
classification: "interactive" | "service_driven" | "batch_scheduled" |
                "mixed" | "apparently_quiet" | "unknown",
interactive_logons: int, remote_interactive_logons: int, batch_logons: int,
service_logons: int, network_logons: int, failed_logons: int,
interactive_principals: [[name, count]] (≤10, humans only — apply the same
  machine-account/noise filter as frequency),
first_interactive: ISO|null, last_interactive: ISO|null,
window_days: float|null
```
classification rules (deterministic, in order):
- no logon observations at all → unknown
- (interactive+remote_interactive) ≥ 5 and batch+service logons <
  2×interactive → interactive
- batch logons ≥ 5 and ≥ 2×(interactive+remote_interactive) → batch_scheduled
- service logons ≥ 5 and ≥ 2×(interactive+remote_interactive) → service_driven
- (interactive+remote_interactive) ≥ 1 and (batch+service) ≥ 5 → mixed
- all counts < 5 → apparently_quiet
- else mixed
Conclusion text must state counts and the window ("2 administrator RDP
sessions over 17 days; no other interactive activity observed").

### configured_but_unobserved (analyzer: configured_unobserved) — one per
item; evidence_class configured. Only emitted when the bundle contains
historical evidence (some eventlog observations) — otherwise emit a single
limitation instead ("cannot assess dormancy without history").
Emit for:
- service_state with start_mode auto|manual, state stopped, and zero
  service_activity/process_activity observations referencing it in history.
  (match service name case-insensitively against service and message fields)
- scheduled_task_state enabled, with zero scheduled_activity observations for
  its path AND (last_run null or older than window start).
- installed_role where a role→indicator map finds no matching running
  service/listening port/activity. Map (only these):
  Web-Server → services w3svc/iis*, listening 80/443/8080;
  DNS → service dns, listening 53; DHCP → service dhcpserver;
  FS-DFS-* → service dfs*; Print-Server → service spooler AND listening 515/631
  (spooler alone runs everywhere — do not flag Print-Server if spooler runs);
  WDS / WSUS / Web-Ftp-Server similar spirit — keep the map small and literal.
details: `kind`: "service"|"scheduled_action"|"role", `name`,
`configured_state` (str, e.g. "auto-start, stopped"), `window_days`
(float|null), `note` (str|null).
Conclusion phrasing follows negative-evidence discipline ("configured but no
execution observed during the N-day available history").
Cap: 15 findings, prioritized by start_mode auto first, then name; note
omissions.

### role_inference (analyzer: roles) — zero or more; evidence_class inferred.
Reads prior findings + observations. Every rule sets rule_id and copies the
supporting_observations of the findings it built on (cap 50). Rules
(implement exactly these, no cleverness):

- `role.batch.v1` — any recurring_scheduled_activity with count ≥5, cadence ≠
  irregular, and a non-null principal or process. Confidence HIGH if count ≥10
  and cadence in (daily, hourly, interval, weekdays); else MEDIUM.
  Role string: "batch/scheduled processing host".
- `role.db_client.v1` — peer_dependency with service_hint in (mssql, oracle,
  mysql, postgresql, redis, mongodb) AND no local service_state whose name
  matches a known DB service (mssql*, sqlserver*, mysql*, postgres*, oracle*,
  redis, mongod*) in state running AND no socket_state listening on that same
  port. HIGH if evidence "both" or count ≥5; else MEDIUM. Role: "database
  client (talks to <host>:<port>)".
- `role.transfer_client.v1` — peer_dependency with service_hint ssh/sftp or
  smtp, count ≥2. MEDIUM (HIGH if count ≥5 and evidence both).
  Role: "outbound file-transfer/messaging client (<hint> to <host>)".
- `role.web_server.v1` — socket_state listening on 80/443/8080/8443 whose
  owning process or a running service matches (w3wp, iis, w3svc, httpd,
  nginx, tomcat, apache) OR installed_role Web-Server present AND w3svc
  running. HIGH if listening + matching running service; MEDIUM if only
  installed+running without observed listening. Role: "web server".
- `role.db_server.v1` — running DB-named service AND listening on its port
  (1433/1521/3306/5432/6379/27017). HIGH. Role: "database server".
- `role.dc.v1` — host_identity domain_role indicates domain controller, or
  services ntds+kdc running. HIGH. Role: "domain controller / identity
  infrastructure".
- `role.admin_host.v1` — interactive_use classification "interactive" AND no
  role.batch.v1 emitted AND peer_dependency findings ≤3. MEDIUM if
  remote_interactive_logons ≥5 else LOW. Role: "interactive administration /
  jump host".
- `role.quiet.v1` — interactive_use classification "apparently_quiet" AND no
  recurring_scheduled_activity findings AND total historical observations
  < 200. LOW. Role: "apparently quiet during observed window". Conclusion
  must name the window length and that this is not evidence the host is
  unused.
Multiple roles are allowed and expected. Each finding's details:
`{role: str, evidence_summary: [str] (one bullet per contributing signal)}`.

### limitation (analyzers: coverage mainly; any analyzer may emit) —
evidence_class unknown. details: `{kind: str, subject: str|null}` where kind
is a short slug (`channel_disabled`, `retention_short`, `truncated`,
`collector_error`, `no_process_auditing`, `no_security_log`, `no_history`,
`analyzer_failed`, `capped`). Conclusion is the human sentence.

## 5. Analyzer module map

| module (analyzers/)       | class                    | name                  |
|---------------------------|--------------------------|-----------------------|
| coverage.py               | CoverageAnalyzer         | coverage              |
| frequency.py              | FrequencyAnalyzer        | frequency             |
| recurrence.py             | RecurrenceAnalyzer       | recurrence            |
| correlation.py            | CorrelationAnalyzer      | correlation           |
| associations.py           | AssociationsAnalyzer     | associations          |
| peers.py                  | PeersAnalyzer            | peers                 |
| interactive.py            | InteractiveAnalyzer      | interactive           |
| configured_unobserved.py  | ConfiguredUnobservedAnalyzer | configured_unobserved |
| roles.py                  | RolesAnalyzer            | roles                 |

Each module also exposes `ANALYZER = <TheClass>()` at module level for
registry wiring. Collector modules likewise expose `COLLECTOR = <TheClass>()`.
Do not edit the `__init__.py` registries — the integrator wires them.

## 6. Report contract

`report/text.py` → `render_text(result: AnalysisResult) -> str`.
`report/json_out.py` → `render_json(result: AnalysisResult) -> dict`.

Text sections, in order, each omitted only if it has genuinely nothing to say
(coverage/limitations always render):

```
HOST                       (manifest + host_identity observation)
EVIDENCE                   (evidence_coverage: per-channel spans, top rows)
LIKELY ROLES               (role_inference: role + confidence, or explicit
                            "No role inference met evidence thresholds")
PRIMARY RECURRING ACTIVITY (recurring_scheduled_activity + activity_episode)
ASSOCIATED EXECUTION       (process_association, grouped by process)
OBSERVED PEERS             (peer_dependency: host:port, hint, count, evidence)
CONFIGURED BUT NOT OBSERVED(configured_but_unobserved)
INTERACTIVE USE            (interactive_use conclusion + top principals)
ACTIVITY SUMMARY           (frequency_summary, compact: top providers,
                            processes, principals — a few lines, not a dump)
LIMITATIONS                (limitation findings, one line each)
```

Every rendered conclusion line includes its finding ID in brackets, e.g.
`[f-0007]`, so the JSON/finding provenance is reachable from the text.
Two-space indents, UPPERCASE section headers, no ANSI colors, no tables
wider than 100 chars.

`render_json(result)` returns:
```
{
  "schema_version": 1,
  "host": {...manifest hostname/platform + host_identity attributes},
  "manifest": {tool_version, collection_start, collection_end,
               requested_since, since_resolved, collectors},
  "observations_summary": result.observations_summary,
  "evidence_coverage": details of the coverage finding,
  "recurring_activity": [details+id+conclusion+confidence of each recurrence],
  "episodes": [... activity_episode ...],
  "associations": [...],
  "dependencies": [... peer_dependency ...],
  "interactive_use": {...},
  "configured_but_unobserved": [...],
  "role_inferences": [...],
  "limitations": [...],
  "findings": [every finding via to_json_dict()]
}
```
All lists preserve finding order. The JSON must round-trip through
`json.dumps` (no datetime objects, only strings).

## 7. Testing conventions

- Tests live in `tests/`, named `test_<module>.py`. Use pytest, no test deps
  beyond pytest.
- `tests/helpers.py` provides:
  - `make_obs(**kwargs) -> Observation` — sensible defaults (id auto-seq,
    source "test", category required, timestamp optional ISO str).
  - `make_manifest(**overrides) -> dict` — minimal valid manifest
    (schema_version 1, hostname "testhost", platform "windows",
    collection_start/end ISO, requested_since "72h", since_resolved ISO,
    collectors []).
  - `build_ctx(observations, manifest=None, options=None)` — wraps
    `analyzers.base.build_context`.
  - `FakePowerShell(responses)` — `responses` is an ordered list of
    `(substring, payload)` pairs; `run_json`/`run_jsonl`/`run_text` find the
    first pair whose substring occurs in the script and return the payload
    (for run_jsonl the payload is a list; for run_text a str). Unmatched
    scripts raise AssertionError listing the script. Records all scripts in
    `.calls`.
- Collector tests: feed FakePowerShell canned payloads (realistic shapes,
  including missing fields, empty lists, permission-denied errors) and assert
  normalized observations + errors. Include at least one malformed-payload
  case per collector.
- Analyzer tests: synthetic observations via make_obs; test both the rule
  firing AND a counterexample that must NOT fire (over-inference guard).
- Determinism test style: run twice, compare full serialized output.

## 8. Integration wiring (integrator only)

Collector registry order: eventlog, services, scheduled_tasks, processes,
network, host_identity, software.
Analyzer registry order: coverage, frequency, recurrence, correlation,
associations, peers, interactive, configured_unobserved, roles.
