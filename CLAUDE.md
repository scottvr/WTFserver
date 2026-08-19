# AGENTS.md

## Project

This repository contains WTFServer / `whatami`.

The immediate goal is to determine whether deterministic analysis of ordinary local Windows evidence can produce a useful functional portrait of an unfamiliar server.

The core question is:

> What does this machine appear to do?

This project is not primarily a forensic toolkit, SIEM, monitoring system, CMDB, vulnerability scanner, or AI assistant.

The value proposition is correlation and operational interpretation.

---

# Authoritative project documents

Before implementing non-trivial work, read:

```text
WTFServer_Product_and_Architecture_Direction.md
WTFServer_First_Build.md
```

Use them for different purposes:

```text
WTFServer_Product_and_Architecture_Direction.md
    Long-term product and architectural direction.

WTFServer_First_Build.md
    Current implementation scope and proof-of-concept boundary.

AGENTS.md
    Engineering rules and constraints for agents working in this repository.
```

When the documents appear to conflict, prefer:

1. explicit current task instructions
2. `AGENTS.md` engineering constraints
3. `WTFServer_First_Build.md` for current scope
4. `WTFServer_Product_and_Architecture_Direction.md` for long-term direction

Do not silently resolve substantive architectural ambiguity. Surface it to the orchestrating agent.

---

# Primary engineering objective

Build the smallest implementation capable of testing this hypothesis:

> Can locally available Windows state and historical evidence be transformed into an evidence-backed operational portrait that is materially more useful than a collection of inventory files and raw event logs?

The first implementation should answer questions such as:

```text
What appears to happen on this host?
What repeats?
Who or what initiates it?
What processes and services are involved?
What other systems appear involved?
What evidence supports those conclusions?
What important evidence is unavailable?
```

The first implementation does not need to identify the exact business application or organizational owner.

---

# Architectural invariants

These constraints are intentional.

Do not violate them merely because a narrower implementation would be easier.

## 1. Separate collection from analysis

The architecture should preserve this flow:

```text
platform-specific collectors
        |
        v
normalized observations
        |
        v
deterministic analyzers
        |
        v
structured findings
        |
        v
reports
```

Collectors gather evidence.

Collectors do not decide what the host "is."

Analyzers consume normalized observations.

Reports present findings.

Do not embed role inference inside Windows collection code.

---

## 2. Windows is the first platform, not the core abstraction

Windows Server is the current implementation target.

It is not the intended architectural boundary.

Do not encode assumptions into core interfaces that would make future Linux support require redesign.

Avoid core assumptions such as:

```text
all event history is EVTX
all scheduled execution is a Windows Scheduled Task
all services use Windows SCM semantics
all principals are DOMAIN\User
all paths use drive letters
all configuration comes from the registry
```

Windows-specific collectors may understand those concepts.

The normalized model and inference layer should use broader concepts where practical.

Prefer concepts such as:

```text
principal
process
service
scheduled_action
peer
path
activity
observation
finding
evidence
```

Platform-specific details may remain in source-specific metadata.

---

## 3. External systems are optional evidence sources

The core tool must not require:

```text
Splunk
Elastic
Graylog
OpenTelemetry
CMDB
SCCM / MECM
monitoring platforms
cloud APIs
virtualization APIs
vendor-specific products
```

Such systems may eventually provide valuable additional evidence.

Design so that external evidence providers can be added later without becoming mandatory infrastructure.

Do not create dependencies on them during the first build.

---

## 4. Preserve future provider/plugin boundaries

Do not build a plugin marketplace or generalized plugin SDK during the first implementation.

Do avoid designs that would make one difficult later.

Collection should conceptually support independent providers such as:

```text
local_windows
local_linux
splunk
elastic
cmdb
sccm
vmware
aws
vendor_specific_provider
```

Providers should contribute observations or metadata through stable interfaces rather than bypassing analysis and writing conclusions directly.

---

# Deterministic-first rule

The initial implementation must not depend on an LLM, ML model, embedding model, hosted AI service, or opaque classifier.

Inference should initially come from explicit, inspectable logic.

Examples:

```text
repeated scheduled action
+ same executable
+ regular cadence
    -> evidence of batch processing
```

```text
repeated outbound connections to SQL service
+ no local DB service
    -> evidence of database-client behavior
```

```text
service configured
+ no observed execution during retained history
    -> configured-but-unobserved finding
```

Every inference should be explainable.

A future AI layer may consume structured evidence and findings for summarization, hypothesis generation, or operator interaction.

The intended layering is:

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

Do not implement:

```text
raw logs
    |
LLM
    |
answer
```

as the core architecture.

---

# Evidence discipline

The tool must distinguish among:

```text
Configured
Observed
Inferred
Unknown
```

Do not collapse them.

Example:

```text
Configured:
  IIS role is installed.

Observed:
  No IIS-related workload activity was observed during available history.

Inferred:
  IIS may be unused or associated with a dormant workload.

Unknown:
  Whether IIS is required during infrequent business events.
```

---

# Negative evidence discipline

Absence of evidence is not automatically evidence of absence.

Prefer:

```text
No IIS activity was observed during the available 17-day history.
```

over:

```text
This is not a web server.
```

Prefer:

```text
No interactive logons were observed.
```

over:

```text
Nobody uses this interactively.
```

The available observation window must remain visible when interpreting negative findings.

---

# Evidence coverage is first-class data

Before interpreting host behavior, determine what evidence is actually available.

Where possible, record:

```text
source
enabled/available state
oldest observation
newest observation
record count
collection errors
known limitations
```

Do not assume all sources cover the requested time range.

`--since 72h` means:

> Analyze up to 72 hours where evidence exists.

It does not mean:

> Pretend every source contains 72 hours of history.

---

# Provenance requirement

Every substantive finding should be traceable to supporting observations.

A finding should eventually be capable of representing:

```text
finding ID
finding type
conclusion
confidence
rule/analyzer ID
supporting observation IDs
limitations
```

Do not emit opaque conclusions that cannot be explained.

Avoid fake precision.

Prefer:

```text
HIGH
MEDIUM
LOW
```

over:

```text
87.314% confidence
```

unless a future scoring model has a defensible empirical basis.

---

# Current first-build scope

The first implementation targets:

```text
Windows Server 2016+
single host
local collection
offline analysis
CLI reporting
```

Initial evidence sources should include:

```text
Windows Event Log inventory
Windows Event Log history
services
scheduled tasks
running processes
current network state
basic host identity
installed roles/features
installed software
```

Do not expand scope merely because adjacent information is easy to collect.

Collection is not the product.

Interpretation is the product.

---

# First-build outputs

The first useful workflow should resemble:

```text
whatami collect --since 72h --output host.wtf
whatami analyze host.wtf
```

A convenience command may eventually combine them.

Collection and analysis should remain separable.

This supports:

```text
offline analysis
repeatable tests
re-analysis after analyzer improvements
sharing bundles
development without repeatedly touching production hosts
```

---

# Bundle format

Use a versioned collection bundle.

An initial form may be:

```text
manifest.json
observations.jsonl
raw/
```

Do not overdesign the bundle.

Do version it from the start.

The manifest should contain enough provenance to understand:

```text
which host was collected
which platform was observed
when collection occurred
what time range was requested
which collectors ran
which collectors failed
which schema/tool version produced the bundle
```

---

# Normalized observation model

Keep the initial model small and extensible.

Conceptually:

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

Most fields may be absent for most observations.

That is acceptable.

Do not prematurely invent a large inheritance tree for every Windows event type.

Prefer a simple stable core plus source-specific attributes.

---

# Analyzer design

Analyzers should be modular.

Conceptually:

```text
Analyzer
    name
    required observation categories
    analyze()
    findings produced
```

Good initial analyzers include:

```text
evidence coverage
frequency counts
scheduled recurrence
simple temporal clustering
process/principal associations
peer/dependency hints
interactive-use hints
configured-but-unobserved detection
basic role inference
```

Do not build sophisticated causal inference before simple correlation has proven useful.

---

# Correlation philosophy

Start simple.

A useful first mechanism may be:

```text
anchor event
    |
nearby observations within configurable time window
    |
repeated similar clusters
```

For example:

```text
scheduled action starts
service account logs on
process executes
remote peer is contacted
files are touched
scheduled action completes
```

If that pattern repeats 21 times, reporting the repeated episode is already useful.

Do not introduce complex statistical models unless simpler mechanisms fail.

---

# Reports

The default report should be terminal-friendly.

Prefer information such as:

```text
HOST
EVIDENCE COVERAGE
LIKELY ROLES
PRIMARY RECURRING ACTIVITY
ASSOCIATED EXECUTION
OBSERVED PEERS
CONFIGURED BUT NOT OBSERVED
INTERACTIVE USE
LIMITATIONS
```

Machine-readable JSON should also be available.

Do not build a GUI during the first implementation.

---

# Testing expectations

Tests should cover both mechanics and semantics.

At minimum:

## Collector tests

Verify:

```text
source parsing
normalization
missing fields
permissions failures
empty sources
malformed source data
```

## Analyzer tests

Use synthetic observations to verify that explicit rules produce expected findings.

For example:

```text
21 nightly executions
+ same principal
+ same process
    -> batch-processing evidence
```

Also test counterexamples to prevent over-inference.

## Bundle tests

Verify:

```text
schema/version handling
round-trip serialization
missing optional data
unknown attributes
```

## Regression fixtures

Where licensing and privacy permit, maintain sanitized or synthetic evidence bundles representing known host patterns.

These should allow deterministic regression testing without needing a live Windows server for every test.

---

# Validation target

The initial concept should be tested against multiple known Windows hosts with meaningfully different purposes.

Useful candidates:

```text
web/application server
batch/integration server
mostly-idle or administration-oriented server
```

The question is not whether the program guesses the official CMDB role string.

The question is whether an experienced engineer reading the report can reconstruct the host's operational character.

Example success:

```text
"This is clearly some kind of nightly integration server.
It runs this executable under this account, talks to that database,
and appears to send data over SFTP."
```

That is sufficient.

---

# Stop/go criterion

Continue development only if correlation and inference produce something materially more useful than:

```text
services.txt
tasks.txt
netstat.txt
eventlogs.csv
```

If the tool merely formats inventory more pleasantly, reconsider the premise.

Do not compensate for weak inference by adding more collection.

---

# Scope exclusions for the first build

Do not implement unless explicitly directed:

```text
GUI
web frontend
central controller
multi-host orchestration
persistent endpoint agent
central database
Splunk integration
Elastic integration
CMDB integration
plugin marketplace
Linux collectors
cloud discovery
graph database
packet capture
memory forensics
malware detection
Sigma rules
threat hunting
vulnerability scanning
CVE analysis
compliance frameworks
LLM summarization
LLM inference
ML classification
retirement automation
```

These are possible future directions, not first-build requirements.

---

# Guidance for delegated agents

When working on a delegated subtask:

1. Stay within the requested scope.
2. Read relevant existing interfaces before inventing new ones.
3. Do not redesign unrelated components.
4. Do not introduce platform-specific assumptions into shared abstractions.
5. Do not add dependencies merely for convenience when the standard library or existing dependency already suffices.
6. Preserve deterministic behavior.
7. Add tests for new behavior.
8. Preserve provenance and explainability.
9. Handle partial evidence and collection failures gracefully.
10. Return useful partial results rather than treating one unavailable source as total failure.

If a task appears to require violating an architectural invariant, surface the conflict to the orchestrating agent rather than silently implementing around it.

---

# Dependency policy

Prefer a small dependency surface.

Before adding a library, determine:

```text
What capability does it provide?
Is that capability already available?
Does it become part of a core architectural dependency?
Is it maintained?
Does it create platform restrictions?
Can it operate offline?
```

Do not reject useful libraries merely to achieve dependency purity.

Do not casually turn optional capabilities into mandatory dependencies.

Platform-specific dependencies should remain isolated from platform-neutral core logic where practical.

---

# Failure behavior

This tool will frequently run on strange, neglected, partially broken systems.

Expect:

```text
permission failures
disabled logs
missing providers
corrupt or inaccessible records
unexpected vendor software
partial event history
services with invalid paths
tasks referencing missing executables
network peers that no longer resolve
old OS behavior
localized or unusual configurations
```

Partial failure is normal.

Collectors should report errors and continue where safe.

Analysis should explicitly account for missing evidence.

Do not convert "collector X failed" into "host analysis failed" unless the missing information makes analysis impossible.

---

# Implementation style

Favor:

```text
small modules
explicit interfaces
typed data structures
deterministic functions
testable transformations
clear provenance
boring serialization
useful CLI output
```

Avoid:

```text
monolithic scripts
hidden global state
business logic inside collectors
parsing mixed with presentation
opaque scoring
premature frameworks
premature distributed architecture
Windows assumptions in core types
AI-generated conclusions without evidence
```

Readable boring code is preferred over clever code.

---

# Naming

The project may be referred to as:

```text
WTFServer
```

The user-facing CLI is expected to center around:

```text
whatami
```

Do not spend implementation effort resolving branding or naming beyond what is necessary for packaging and CLI invocation.

---

# Current milestone

The first milestone is reached when:

```text
whatami collect --since 72h
whatami analyze <bundle>
```

can produce an evidence-backed report answering:

```text
What appears to happen on this host?
What repeats?
Who or what initiates it?
What other systems appear involved?
What evidence supports the conclusions?
What important evidence is missing?
```

Nothing beyond that is required to justify the next phase.

Build toward evidence, correlation, and explanation.

Do not build the empire before proving that the question can be answered.