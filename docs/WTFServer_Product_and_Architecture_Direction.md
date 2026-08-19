# WTFServer / `whatami`

## Product and Architecture Direction

### Working premise

Given access to an unfamiliar server, answer:

> What does this machine appear to do?

using information that can be observed or reconstructed from the machine itself, plus optional external evidence sources when available.

The initial target is Windows Server because that is the immediate problem domain. Windows is not the intended architectural boundary.

The longer-term product should be capable of answering the same class of question for other operating systems and environments without requiring a redesign of the core model.

This is not primarily:

- incident response
- malware detection
- compliance auditing
- vulnerability assessment
- forensic evidence preservation
- configuration inventory
- monitoring
- CMDB replacement
- application performance monitoring

Those systems may provide useful evidence. The desired output is a **functional portrait of the host**.

The tool should turn system state, retained historical events, configuration, and optional external observations into a human-readable explanation of the server's apparent purpose, dependencies, recurring behaviors, and uncertainties.

---

# 1. Core questions

A useful implementation should attempt to answer:

1. What workloads appear to run here?
2. What happens repeatedly?
3. Which users or service accounts cause activity?
4. What other systems does this host communicate with?
5. What files, directories, services, or tasks appear operationally important?
6. What components drive observed activity?
7. Is the machine primarily interactive, service-oriented, batch-oriented, infrastructural, or apparently idle?
8. How far back can the available evidence actually tell us anything?
9. What conclusions can reasonably be inferred from that evidence?
10. What remains unknown?

The last two are first-class output.

The tool should distinguish:

```text
Observed:
  Scheduled task \Vendor\Export executed 23 times.

Inferred:
  Host probably performs a nightly data export.

Unknown:
  Destination business purpose cannot be determined locally.
```

---

# 2. Fundamental design principle: observations before conclusions

The architecture should preserve a strong boundary between:

- collection
- normalization
- correlation
- inference
- presentation

Collectors should produce observations.

Inference should consume observations.

Presentation should render conclusions while preserving the evidence chain.

This separation matters because:

- collection methods will differ by operating system
- evidence sources will differ by environment
- inference rules should be independently testable
- third-party integrations should not leak into core logic
- future agents or contributors should be able to implement one component without silently coupling the system to Windows-specific assumptions

A Windows event log is an evidence source, not the ontology.

A scheduled task is one implementation of recurring execution, not the universal abstraction.

A Windows service is one implementation of a long-running service, not the universal abstraction.

The internal representation should use portable concepts where practical.

---

# 3. Initial operating modes

## Current-state inspection

Conceptually:

```text
whatami --now
```

Inspect things such as:

- running processes
- process command lines
- services
- listening sockets
- established connections
- scheduled execution mechanisms
- logged-on users
- network shares
- mounted storage
- installed system roles/features
- application configuration
- installed applications
- startup mechanisms

This tells us what the host is doing or capable of doing **right now**.

## Historical inspection

```text
whatami --since 72h
```

Use whatever historical evidence remains locally to reconstruct recent behavior.

Desired time selectors:

```text
--since 12h
--since 3d
--since 2026-08-01
--since max
```

`--since max` should mean:

> Use the maximum locally available history from every useful source.

It should not imply that all sources have equal retention.

---

# 4. Evidence inventory

Before drawing conclusions, inventory what evidence actually exists.

For each source, determine where possible:

- whether it is enabled or available
- record/object count
- oldest retained observation
- newest retained observation
- source identity
- apparent observation frequency
- known limitations
- collection errors

For Windows Event Logs, this may include:

- enabled/disabled
- record count
- current size
- maximum size
- oldest retained event
- newest retained event
- provider(s)

Example:

```text
Evidence coverage

Security
  oldest: 2026-06-14
  newest: 2026-08-19
  records: 487,221

System
  oldest: 2026-07-02
  newest: 2026-08-19
  records: 31,892

Microsoft-Windows-TaskScheduler/Operational
  oldest: 2026-08-03
  newest: 2026-08-19
  records: 8,201

VendorThing/Operational
  oldest: 2026-08-18 22:41
  newest: 2026-08-19
  records: 91,424
```

Evidence coverage is part of the answer, not just debug information.

---

# 5. Evidence sources

The first implementation targets locally available Windows evidence, including:

- Windows Event Logs
- services
- scheduled tasks
- running processes
- current network state
- Windows roles/features
- installed software
- startup mechanisms
- selected application configuration

Event collection should not be limited to:

```text
Application
Security
System
```

Particular attention should be paid to:

- TaskScheduler
- PowerShell
- WinRM
- WMI
- Terminal Services / RDP
- SMB client/server
- DNS client
- Group Policy
- Service Control Manager
- Windows Update
- application-specific providers
- vendor-created channels

Unknown providers should initially be treated as potentially useful rather than discarded as noise.

---

# 6. Normalized observation model

Heterogeneous evidence should normalize into a portable internal representation.

Conceptually, an observation might contain:

```text
timestamp
source
source_type
host
category
action
principal
process
service
scheduled_action
remote_host
remote_port
local_path
object
message
attributes
raw_reference
```

Not every observation will populate every field.

The schema should avoid baking Windows vocabulary into the core where an OS-neutral term exists.

Examples:

- `scheduled_action` rather than requiring `scheduled_task`
- `principal` rather than requiring `DOMAIN\User`
- `service` as an abstract service identity, with platform-specific metadata attached separately
- `remote_host` and `remote_port` rather than a Windows networking abstraction

Platform-specific details should remain available in attributes or source-specific extensions.

---

# 7. Timeline normalization

Normalize historical observations into a common chronological stream.

The normalized timeline should be exportable:

```text
whatami --since 72h --jsonl timeline.jsonl
whatami --since 72h --csv timeline.csv
```

This allows the operator to discard the higher-level inference entirely and investigate manually.

That escape hatch is a feature.

---

# 8. Frequency and periodicity analysis

Automatically identify dominant and unusual activity.

Examples:

```text
Top event providers
Top event IDs
Top processes
Top services
Top scheduled actions
Top principals
Top remote hosts
Top remote ports
Top filesystem paths
```

Identify temporal patterns such as:

```text
daily at approximately 01:00
every 15 minutes
weekdays around 07:30
only during interactive logons
activity immediately following reboot
```

Periodic behavior is likely to be one of the strongest signals of machine purpose.

---

# 9. Activity clustering

Correlate nearby observations into episodes.

For example:

```text
01:00:00  svc_export batch logon
01:00:01  scheduled task VendorExport started
01:00:02  export.exe launched
01:00:04  connection to db01:1433
01:02:37  file created D:\Outbound\customers.csv
01:02:40  connection to sftp.vendor.com:22
01:03:11  scheduled task completed
```

should preferably become:

```text
Recurring activity cluster: Nightly export

Observed 21 times over 23 days.

Typical sequence:
  svc_export logon
  -> VendorExport scheduled action
  -> export.exe
  -> db01:1433
  -> D:\Outbound
  -> sftp.vendor.com:22
```

This is closer to the actual product value than listing individual events.

---

# 10. Dependency inference

Construct a rough dependency graph from observed behavior.

Example:

```text
crypt01
 |
 +-- svc_export
 |
 +-- VendorExport scheduled action
 |    |
 |    +-- export.exe
 |
 +--> db01:1433
 |
 +--> sftp.vendor.com:22
 |
 +--> D:\Outbound
```

Evidence-backed relationships should retain provenance.

The graph does not initially need a graphical renderer. A machine-readable representation is sufficient.

---

# 11. Role inference

Infer broad host roles conservatively.

Possible classifications:

```text
web server
application server
database server
file server
batch-processing host
integration/ETL host
jump host
monitoring server
backup server
identity/domain infrastructure
build/deployment worker
vendor appliance/application host
interactive workstation-like server
apparently dormant
unknown
```

Multiple roles must be allowed.

Example:

```text
Probable roles

Batch integration host       HIGH
SFTP transfer endpoint       HIGH
SQL client                   HIGH
Interactive administration   LOW
Web server                   NONE OBSERVED
```

Do not force every machine into exactly one category.

---

# 12. Deterministic inference first

The initial implementation should prefer deterministic and explainable inference.

Examples:

- repeated scheduled execution at the same time
- stable process-to-peer relationships
- recurring principal/task/process chains
- recurring path usage
- role hints from installed services or features
- evidence of interactive versus service-oriented usage
- repeated dependency edges

The first useful implementation should not depend on an LLM.

This is partly practical and partly epistemic.

If an inference is wrong, we should be able to determine:

- which observations caused it
- which rule produced it
- whether the rule is defective
- whether evidence was insufficient

An LLM can later be useful for:

- summarization
- natural-language explanation
- hypothesis generation
- interpreting unfamiliar vendor text
- correlating weak signals
- operator Q&A

But AI should initially sit **above** a deterministic evidence and inference layer, not replace it.

No core result should require an opaque "AI confidence" score.

---

# 13. Confidence and provenance

Every inference should expose confidence and supporting evidence.

Example:

```text
Probable purpose:
  Nightly customer-data export intermediary

Confidence:
  HIGH

Supporting evidence:
  - Scheduled action executed on 21 of 23 retained days
  - Same executable launched after each execution
  - Same service account used in all observed executions
  - Connections to db01:1433 correlate with execution
  - Files appear under D:\Outbound during each execution window
```

Conversely:

```text
Possible role:
  Legacy reporting server

Confidence:
  LOW

Reason:
  SQL client libraries and report templates are installed,
  but no execution evidence was found within retained history.
```

Every significant conclusion should be traceable back to raw or normalized observations.

---

# 14. Negative evidence

Absence should be reported carefully.

Good:

```text
No IIS activity was observed during the available 17-day history.
```

Bad:

```text
This is not a web server.
```

Likewise:

```text
No interactive logons observed.
```

is different from:

```text
Nobody uses this interactively.
```

The report should respect the distinction between lack of evidence and evidence of absence.

---

# 15. Static versus observed versus inferred state

Explicitly distinguish:

```text
Configured
Observed
Inferred
```

Example:

```text
Configured:
  Apache Tomcat service exists.

Observed:
  Service did not run during available history.

Inferred:
  Tomcat may represent a retired workload.
```

This distinction may be particularly valuable for retirement and migration analysis.

---

# 16. Human-readable report

The default output should probably be terminal-friendly text rather than a dashboard.

Example:

```text
PS> whatami --since 30d

HOST
  crypt01.example.com
  Windows Server 2016
  Evidence available: approximately 23 days

PROBABLE PURPOSE
  Legacy batch integration / outbound data transfer host

CONFIDENCE
  HIGH

PRIMARY ACTIVITY
  Scheduled action \Vendor\NightlyExport
  Usually runs at 01:00
  Observed 21 times

EXECUTION CHAIN
  DOMAIN\svc_export
    -> export.exe
    -> db01.example.com:1433
    -> D:\Outbound
    -> sftp.vendor.com:22

IMPORTANT PATHS
  D:\Vendor
  D:\Outbound
  D:\Archive

OBSERVED DEPENDENCIES
  db01.example.com:1433
  sftp.vendor.com:22
  dc02.example.com

INTERACTIVE USE
  3 administrator RDP sessions
  No ordinary-user interactive activity observed

OTHER FINDINGS
  IIS installed but no activity observed.
  Legacy VendorService exists but has not started during retained history.

UNKNOWN
  Business owner
  Meaning of exported dataset
  Whether downstream consumer remains active
```

---

# 17. Machine-readable report

Everything in the human-readable report should also have structured output:

```text
--json
--yaml
```

This enables:

- fleet scans
- CMDB enrichment
- migration discovery
- retirement analysis
- dependency mapping
- comparison across environments
- downstream analytics
- optional LLM consumption without forcing an LLM to parse raw system logs

---

# 18. Explainability

Something like:

```text
whatami --explain "batch integration host"
```

should show exactly why the conclusion was reached.

No opaque:

```text
AI confidence: 87%
```

without evidence.

---

# 19. No mandatory external infrastructure

A useful standalone implementation should require:

- no Splunk
- no Elastic
- no CMDB
- no APM platform
- no agent deployment
- no existing telemetry pipeline
- no cloud service
- no database server

Run it against the machine and use what is already there.

External systems should improve the answer when available, not be prerequisites for producing one.

---

# 20. External integrations and plugin architecture

Long term, the system should support evidence from common enterprise systems.

Examples include:

- Splunk
- Graylog
- Elastic
- OpenTelemetry collectors/backends
- SIEM platforms
- CMDBs
- SCCM / MECM
- monitoring systems
- asset inventory platforms
- endpoint management systems
- virtualization platforms
- cloud inventory APIs
- backup products
- vendor-specific application tooling

These integrations should be optional evidence providers.

The core should not contain hard dependencies on any single product.

A plugin/provider interface should eventually allow vendor and community extensions.

Conceptually:

```text
providers/
    local_windows
    local_linux
    splunk
    graylog
    elastic
    cmdb
    sccm
    vmware
    aws
    vendor_x
```

Providers should contribute observations and metadata through stable interfaces rather than bypassing the core data model.

An external CMDB entry saying:

```text
Application: Payroll Export
Owner: Finance Apps
```

is evidence.

It should complement, not silently overwrite, observations from the host.

Conflicts between evidence sources should be representable.

---

# 21. Platform independence as an architectural requirement

Windows is the first target, not the product definition.

The architecture should leave room for Linux and other environments without forcing Windows semantics into core interfaces.

For example, Linux equivalents might include:

- systemd services
- cron/systemd timers
- journald
- syslog
- auditd
- package managers
- `/proc`
- sockets
- shell/login history
- application logs

The higher-level concepts remain similar:

```text
principal
process
service
scheduled action
peer
path
activity
dependency
role
evidence coverage
```

Platform-specific collectors translate their native sources into those abstractions.

Contributors implementing Windows features should not be allowed to make assumptions such as:

```text
all services have Windows Service Control Manager semantics
all scheduled work is a Windows Scheduled Task
all event history comes from EVTX
all principals are DOMAIN\User
all paths use drive letters
```

The first implementation may contain Windows-specific code.

The **core contracts** should not require Windows.

---

# 22. Offline analysis

Collection and analysis should be separable.

Conceptually:

```text
whatami collect crypt01 --output crypt01.wtf
whatami analyze crypt01.wtf
```

Benefits:

- repeated analysis without hammering the server
- easy sharing with another engineer
- deterministic development/testing
- ability to improve inference later
- no need to remain connected to production

The collection bundle might eventually contain:

```text
manifest.json
observations/
events/
state/
tasks/
services/
network/
software/
filesystem/
```

without pretending to be a forensic disk image.

The bundle format should be versioned.

---

# 23. Minimally invasive collection

This is operational discovery.

Defaults should avoid:

- installing persistent services
- enabling audit policies automatically
- restarting services
- changing log retention
- rebooting
- modifying application configuration

If additional telemetry would materially improve the answer, the tool may recommend it:

```text
Insufficient process history.

Process-creation auditing does not appear to be enabled.
Consider enabling it and re-running whatami after 24 hours.
```

But changing the system should require explicit action.

---

# 24. Evidence gaps are first-class output

The report should say things like:

```text
LIMITATIONS

Security log retains only 4.2 hours of history.
Task Scheduler Operational logging is disabled.
No process-creation auditing was detected.
Firewall connection logging is unavailable.
Vendor application logs were discovered but not parsed.
```

This is as important as the conclusions.

---

# 25. Extensibility boundaries

The architecture should assume growth along at least two independent axes:

## More platforms

```text
Windows
Linux
cloud instances
containers
other Unix-like systems
```

## More evidence sources

```text
local host state
local historical logs
centralized logging
CMDB
monitoring
virtualization
cloud inventory
endpoint management
vendor integrations
```

Growth in one axis should not require rewriting the other.

A useful conceptual separation is:

```text
platform collectors
        |
        v
normalized observations
        |
        +------ external evidence providers
        |
        v
correlation / inference
        |
        v
reports / API / CLI
```

---

# 26. Historical comparison

Eventually:

```text
whatami --since 7d
whatami --since 30d
```

could reveal:

```text
Last 7 days:
  essentially idle

Last 30 days:
  four batch executions

Last observed meaningful workload:
  2026-08-02 01:00
```

This expands the question from:

> What is this?

to:

> Is this thing still doing it?

---

# 27. Fleet mode

Possible future behavior:

```text
whatami host1 host2 host3
```

or:

```text
wtfserver scan servers.txt
```

Then compare inferred functions and dependencies.

---

# 28. Before/after comparison

```text
whatami diff crypt01-before.wtf crypt01-after.wtf
```

Potentially useful during migrations or retirement validation.

---

# 29. Host relationship discovery

If several servers are analyzed:

```text
app01 -> db01
app02 -> db01
crypt01 -> db01
crypt01 -> sftp.vendor.com
```

The system begins constructing an application dependency map.

This may eventually become one of the most operationally valuable outputs.

---

# 30. Retirement assessment

Potential future mode:

```text
whatami --retirement-assessment
```

Example:

```text
Retirement confidence: LOW

Reasons for caution:
  - Recurring workload observed within last 24 hours
  - Two other hosts appear to connect to this machine
  - svc_export remains active
```

This should remain evidence-driven rather than pretending to make an authoritative business decision.

---

# 31. Things deliberately omitted initially

Avoid disappearing into:

- full registry forensics
- memory acquisition
- malware detection
- Sigma rule engines
- threat hunting
- packet capture
- vulnerability scanning
- CVE analysis
- compliance frameworks
- elaborate GUI
- central management server
- mandatory ML
- mandatory LLM inference

Any of those may eventually complement the project.

None answers the primary question by itself.

---

# 32. Product test

The simplest definition of success remains:

> Give the report to an engineer who has never seen the server. Can they explain what the machine appears to do, what it depends upon, what evidence supports that conclusion, and what they would investigate next?

If yes, the tool is producing something distinct from inventory, monitoring, and forensic collection.

If not, it is probably just producing a prettier pile of facts.

