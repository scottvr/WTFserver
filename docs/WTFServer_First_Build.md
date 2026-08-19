# WTFServer / `whatami`

## First Build: Establish Whether the Idea Works

This document deliberately describes a **small first implementation**, not the intended final architecture.

The goal is not to produce an MVP suitable for broad distribution.

The goal is to answer one question:

> Can deterministic analysis of ordinary local Windows evidence produce a useful functional portrait of an unfamiliar server?

If the answer is yes, continue.

If the answer is no, stop before building a platform around a bad premise.

---

# 1. Scope

Target exactly one environment initially:

```text
Windows Server 2016+
single host
local collection
offline analysis
CLI output
```

Do not require:

- centralized logging
- CMDB
- Splunk
- Elastic
- OpenTelemetry
- agents
- databases
- cloud services
- AI/LLMs

Do not build Linux support yet.

However, do not make architectural choices that would make Linux support require rewriting the core model.

---

# 2. Architectural constraint

Even in the first implementation, preserve this boundary:

```text
collectors
   |
   v
normalized observations
   |
   v
analysis / inference
   |
   v
report
```

Windows-specific code belongs in collectors.

Inference should operate on normalized concepts wherever practical.

For example, prefer:

```text
principal
process
service
scheduled_action
peer
path
activity
```

over making the inference engine reason directly about:

```text
Windows Event ID 4688
Task Scheduler XML
SCM-specific fields
DOMAIN\User syntax
```

The Windows collector may know those details.

The core should not require them.

---

# 3. First command shape

Aim for something conceptually like:

```text
whatami collect --since 72h --output crypt01.wtf
whatami analyze crypt01.wtf
```

Optionally allow:

```text
whatami inspect --since 72h
```

as a convenience wrapper around both.

Do not spend much time perfecting CLI syntax yet.

---

# 4. First evidence sources

Collect only enough information to test the premise.

## A. Event Log inventory

Enumerate populated Windows Event Log channels.

Record:

```text
log/channel name
enabled state
record count
oldest available event
newest available event
```

This establishes evidence coverage.

## B. Event history

Collect retained events for the requested window from all populated/enabled channels that can be read safely.

At minimum, do not limit collection to:

```text
Application
Security
System
```

Include useful Microsoft and vendor operational channels.

## C. Services

Collect:

```text
service name
display name
state
start mode
executable/path
service account
```

## D. Scheduled tasks

Collect:

```text
task name/path
enabled state
trigger(s)
action(s)
principal
last run
next run
last result
```

## E. Running processes

Collect:

```text
PID
parent PID if available
image
command line
principal if available
start time if available
```

## F. Current network state

Collect:

```text
listening sockets
established connections
local endpoint
remote endpoint
owning process where available
```

## G. Basic host identity

Collect:

```text
hostname
OS/version
domain/workgroup
interfaces
addresses
DNS configuration
```

## H. Installed roles/features and software

Collect enough to provide static role hints.

Do not attempt exhaustive software archaeology yet.

---

# 5. Bundle format

Store collection output in a versioned bundle.

It can initially be a directory or archive.

Suggested shape:

```text
manifest.json
observations.jsonl
raw/
```

`manifest.json` should include:

```text
schema_version
tool_version
collection_start
collection_end
requested_since
hostname
platform
collector results
collector errors
```

`observations.jsonl` should contain normalized observations.

`raw/` may contain source-specific data useful for debugging and future re-analysis.

Do not overdesign the file format.

Version it from the start.

---

# 6. Minimal normalized observation

Start with a deliberately small schema.

Something conceptually like:

```text
timestamp
host
source
category
action
principal
process
service
scheduled_action
remote_host
remote_port
local_path
message
attributes
raw_reference
```

Most fields will be null for most observations.

That is acceptable.

Do not force every source into a rigid event type hierarchy before seeing real data.

---

# 7. First deterministic analyses

Implement only analyses that have a high chance of being useful.

## A. Evidence coverage

Answer:

```text
What history do we actually have?
```

Example:

```text
Security: 19.4 days
System: 47.2 days
TaskScheduler/Operational: 6.1 days
VendorThing/Operational: 11.8 hours
```

## B. Frequency counts

Produce:

```text
top event providers
top event IDs
top principals
top services
top scheduled actions
top processes
top remote peers
top remote ports
```

## C. Recurring scheduled behavior

Identify obvious repeated scheduled-task execution.

Example:

```text
VendorExport
  21 executions
  typically 01:00 +/- 2m
```

Do not attempt fancy generic temporal mining initially.

## D. Repeated process relationships

Identify processes repeatedly associated with:

- scheduled actions
- service execution
- remote peers
- principals

## E. Current dependency hints

From current sockets and repeated historical evidence, identify likely peers.

Example:

```text
db01:1433
sftp.vendor.com:22
```

## F. Interactive-use hints

Use available evidence to estimate whether activity appears mostly:

- interactive
- service-driven
- batch/scheduled
- unknown

Keep this conservative.

---

# 8. First correlation pass

Implement a simple time-window correlation mechanism.

For a selected anchor event such as:

```text
scheduled action start
service start
process start
logon
```

collect nearby observations within a configurable window.

Example:

```text
-5 seconds ... +5 minutes
```

Then determine whether similar clusters repeat.

Do not attempt sophisticated causal inference.

The goal is to transform:

```text
thousands of unrelated events
```

into:

```text
this same little sequence happened 21 times
```

That alone may prove the concept.

---

# 9. First role inference rules

Implement a very small set of explicit rules.

Examples:

```text
Repeated scheduled action
+ same executable
+ same service principal
+ regular cadence
    -> batch-processing role evidence
```

```text
Repeated outbound SQL connections
+ no local DB service
    -> database-client role evidence
```

```text
Web service installed/running
+ listening on HTTP(S) port
    -> web-server role evidence
```

```text
Mostly administrative interactive logons
+ little recurring background workload
    -> possible jump/admin host evidence
```

```text
Configured service exists
+ no observed execution during retained history
    -> configured-but-unobserved evidence
```

Every rule should emit:

```text
conclusion
confidence
supporting observation IDs
rule ID
```

Avoid numerical pseudo-precision initially.

Use something like:

```text
HIGH
MEDIUM
LOW
```

with explicit rule logic.

---

# 10. First report

Produce one terminal-friendly report.

Example:

```text
HOST
  crypt01.example.com
  Windows Server 2016

EVIDENCE
  Security history: 19 days
  System history: 47 days
  Task Scheduler history: 6 days

LIKELY ROLE
  Batch integration host        HIGH

PRIMARY RECURRING ACTIVITY
  \Vendor\NightlyExport
  observed 6 times
  typical start: 01:00

ASSOCIATED EXECUTION
  DOMAIN\svc_export
    -> export.exe

OBSERVED PEERS
  db01.example.com:1433
  sftp.vendor.com:22

CONFIGURED BUT NOT OBSERVED
  IIS
  VendorLegacyService

INTERACTIVE USE
  2 administrator RDP sessions
  no ordinary-user activity observed

LIMITATIONS
  Process creation auditing unavailable
  Task Scheduler history covers only 6 days
```

This report does not need prose generated by AI.

---

# 11. Machine-readable output

Also emit JSON.

At minimum include:

```text
host
evidence_coverage
observations_summary
recurring_activity
dependencies
role_inferences
limitations
```

This is important both for testing and for future integrations.

---

# 12. Explainability requirement

Every reported inference must be traceable to:

```text
rule
supporting observations
source evidence
```

If a conclusion cannot be explained, do not emit it yet.

This will make later development much easier.

---

# 13. What not to build yet

Do not build:

- GUI
- web service
- multi-host controller
- agent
- central database
- Splunk integration
- CMDB integration
- plugin marketplace
- Linux collectors
- cloud inventory
- generalized graph database
- packet capture
- forensic artifact parsing
- malware/security detection
- AI summarization
- LLM reasoning
- complex scoring model
- retirement recommendations

Leave clean extension points.

Do not implement the extensions.

---

# 14. Plugin boundary to preserve now

Even though plugins are not part of the first build, avoid hard-coding collection orchestration around a fixed list of Windows functions.

Use a collector interface conceptually resembling:

```text
Collector
  name
  platform compatibility
  collect()
  produces observation categories
```

Similarly, analysis should be modular:

```text
Analyzer
  name
  required observation categories
  analyze()
  produces findings
```

The exact language-level interface can evolve.

The important thing is to prevent future contributors or coding agents from implementing features directly inside one monolithic command path.

---

# 15. Platform boundary to preserve now

The first implementation may say:

```text
WindowsCollector
```

It should not make the core say:

```text
WindowsServerAnalyzer
```

Prefer:

```text
HostAnalyzer
```

fed by Windows observations.

That distinction is cheap now and expensive later.

---

# 16. AI boundary to preserve now

Do not put an LLM in the execution path.

If AI support is ever added, the likely layering should be:

```text
raw evidence
   |
normalized observations
   |
deterministic analysis
   |
structured findings
   |
optional AI interpretation
```

not:

```text
raw logs
   |
LLM
   |
trust me
```

A future AI layer may be useful.

It should consume structured evidence and findings rather than replace them.

---

# 17. Validation experiment

Test against at least three known Windows servers with meaningfully different purposes.

For example:

```text
known web/application server
known batch/integration server
known mostly-idle or administrative server
```

For each:

1. collect evidence
2. run analysis
3. hide the known role from whoever reads the report if practical
4. compare inferred portrait with actual purpose
5. record false conclusions
6. record important things the report missed

The tool does not need to correctly name the business application.

It should make an experienced engineer say:

```text
Yes, this is obviously some kind of nightly integration box,
it talks to that database and sends something over SFTP.
```

That is sufficient proof.

---

# 18. Stop/go criterion

Continue development if the first implementation can consistently turn local evidence into a portrait that is materially more useful than:

```text
services.txt
tasks.txt
netstat.txt
eventlogs.csv
```

Stop or rethink if the output is merely a formatted inventory.

The value proposition is **correlation and operational interpretation**, not collection.

---

# 19. First milestone

The first milestone is complete when this works:

```text
whatami collect --since 72h
whatami analyze <bundle>
```

and the resulting report lets an engineer answer:

```text
What appears to happen on this host?
What repeats?
Who or what initiates it?
What other systems appear involved?
What evidence supports that conclusion?
What important evidence is missing?
```

Nothing else is required to earn the next round of stabbing.
