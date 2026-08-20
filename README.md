# WTFServer / `whatami`

> What does this machine appear to do?

`whatami` collects ordinary local Windows evidence (event logs, services,
scheduled tasks, processes, network state, installed roles/software), turns it
into normalized observations, and runs deterministic analyzers that produce an
evidence-backed operational portrait of the host — what repeats, who initiates
it, what other systems are involved, and what evidence is missing.

It is not a SIEM, monitoring system, CMDB, vulnerability scanner, or AI
assistant. Every conclusion is traceable to supporting observations and an
explicit rule.

## Usage

On a Windows Server (2016+), collect evidence into a versioned bundle:

```
whatami collect --since 72h --output host.wtf
```

Analyze the bundle anywhere (offline, repeatable):

```
whatami analyze host.wtf
whatami analyze host.wtf --json report.json
```

Or both in one step on the host:

```
whatami inspect --since 72h
```

`--since` accepts `30m`, `72h`, `3d`, `2w`, an absolute date like
`2026-08-01`, or `max` (all locally available history).

## Design

```
platform-specific collectors
        v
normalized observations   (observations.jsonl in the bundle)
        v
deterministic analyzers
        v
structured findings       (rule ID, confidence, supporting observation IDs)
        v
reports                   (terminal text + JSON)
```

Collection and analysis are separable; a `.wtf` bundle (zip: `manifest.json`,
`observations.jsonl`, `raw/`) can be shared and re-analyzed as analyzers
improve. Collection is read-only and requires no external infrastructure.

Findings distinguish **configured** / **observed** / **inferred** / **unknown**,
confidence is `HIGH`/`MEDIUM`/`LOW` with explicit rules (no opaque scores), and
evidence gaps are first-class output.

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Runtime is standard-library only; Windows collection shells out to PowerShell.
Analysis of an existing bundle runs on any OS, which is how the test suite and
synthetic regression fixtures work. See `docs/dev/CONTRACTS.md` for the
binding interface contracts and `CLAUDE.md` for Agent-assisted engineering policy.
