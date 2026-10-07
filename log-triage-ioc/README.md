# Log Triage and IOC Scanner

A small defensive incident response tool. It parses authentication and web
access logs, correlates them against a watchlist of indicators of compromise,
detects common attack patterns, reconstructs an incident timeline and writes
a structured report. This is the first pass an analyst runs during triage, to
answer what happened, when and from where.

No external dependencies, so the detection logic stays fully readable.

## Detections

* **Brute force** many failed logins from one IP against one account
* **Credential stuffing** failed logins against many accounts from one IP
* **Likely account takeover** a success right after a run of failures from
  the same IP
* **Known bad IP** any traffic from an IP on the IOC watchlist

Findings are ranked high severity first and each carries a first seen and
last seen timestamp, the evidence an analyst needs to document the incident.

## Run

```
python triage_cli.py sample_data/auth.log sample_data/access.log --ioc sample_data/iocs.txt
python -m pytest tests/ -q
```

The sample data contains a seeded incident (a brute force that succeeds and a
credential stuffing burst) so the output is non trivial on first run.

## Layout

```
src/triage.py     parsing, detection rules, timeline and report builders
triage_cli.py     command line runner, writes report.json
tests/            9 tests covering each detection and the clean case
sample_data/      seeded auth log, access log and IOC list
```

## Scope

A learning and triage prototype, not a full SIEM. It covers two log formats
and a focused set of rules. A production pipeline would add more parsers,
enrichment (geo IP, threat intel feeds), and correlation across more sources,
built on the same detection model shown here.
