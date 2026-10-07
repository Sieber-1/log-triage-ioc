"""
Log triage and IOC scanner.

Parses authentication and web access logs, correlates them against a list
of indicators of compromise, detects common attack patterns, reconstructs
an incident timeline and produces a structured report.

Built for defensive incident response and digital forensics triage, the
first pass an analyst runs to answer what happened, when and from where.
No external dependencies, so the detection logic stays fully readable.
"""

import json
import re
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime


# One normalised event, whatever the source log format was
@dataclass
class Event:
    timestamp: datetime
    source_ip: str
    user: str
    action: str          # login_success, login_failure, http_request
    detail: str = ""


# A single detection finding, the unit an analyst triages
@dataclass
class Finding:
    severity: str        # high, medium, low
    category: str
    source_ip: str
    description: str
    first_seen: str
    last_seen: str
    count: int


AUTH_LINE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"auth\s+(?P<result>SUCCESS|FAILURE)\s+"
    r"user=(?P<user>\S+)\s+ip=(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
HTTP_LINE = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\w+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})'
)


def parse_logs(lines):
    """Turn raw log lines into normalised Event objects."""
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue

        m = AUTH_LINE.search(line)
        if m:
            ts = datetime.fromisoformat(m.group("ts").replace(" ", "T"))
            action = "login_success" if m.group("result") == "SUCCESS" else "login_failure"
            events.append(Event(ts, m.group("ip"), m.group("user"), action))
            continue

        m = HTTP_LINE.search(line)
        if m:
            try:
                ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                continue
            events.append(
                Event(ts, m.group("ip"), "-", "http_request",
                      detail=f'{m.group("method")} {m.group("path")} {m.group("status")}')
            )
    return sorted(events, key=lambda e: e.timestamp)


class Detector:
    """Runs detection rules over a list of events."""

    def __init__(self, ioc_ips=None, bruteforce_threshold=5):
        self.ioc_ips = set(ioc_ips or [])
        self.bruteforce_threshold = bruteforce_threshold

    def run(self, events):
        findings = []
        findings += self._known_bad_ip(events)
        findings += self._brute_force(events)
        findings += self._credential_stuffing(events)
        findings += self._success_after_failures(events)
        # highest severity first
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(findings, key=lambda f: (order[f.severity], -f.count))

    def _known_bad_ip(self, events):
        hits = [e for e in events if e.source_ip in self.ioc_ips]
        out = []
        for ip, evs in _group_by_ip(hits).items():
            out.append(Finding(
                "high", "known_bad_ip", ip,
                f"Traffic from IP on the IOC watchlist ({len(evs)} events).",
                _fmt(evs[0].timestamp), _fmt(evs[-1].timestamp), len(evs),
            ))
        return out

    def _brute_force(self, events):
        out = []
        fails = [e for e in events if e.action == "login_failure"]
        for ip, evs in _group_by_ip(fails).items():
            if len(evs) >= self.bruteforce_threshold:
                out.append(Finding(
                    "high", "brute_force", ip,
                    f"{len(evs)} failed logins from a single IP, likely password brute force.",
                    _fmt(evs[0].timestamp), _fmt(evs[-1].timestamp), len(evs),
                ))
        return out

    def _credential_stuffing(self, events):
        out = []
        fails = [e for e in events if e.action == "login_failure"]
        for ip, evs in _group_by_ip(fails).items():
            users = {e.user for e in evs}
            if len(users) >= self.bruteforce_threshold:
                out.append(Finding(
                    "high", "credential_stuffing", ip,
                    f"Failed logins against {len(users)} different users from one IP, "
                    f"consistent with credential stuffing.",
                    _fmt(evs[0].timestamp), _fmt(evs[-1].timestamp), len(evs),
                ))
        return out

    def _success_after_failures(self, events):
        """A success right after many failures from the same IP is a likely compromise."""
        out = []
        by_ip = _group_by_ip(events)
        for ip, evs in by_ip.items():
            fail_streak = 0
            for e in evs:
                if e.action == "login_failure":
                    fail_streak += 1
                elif e.action == "login_success":
                    if fail_streak >= self.bruteforce_threshold:
                        out.append(Finding(
                            "high", "likely_account_takeover", ip,
                            f"Successful login as '{e.user}' after {fail_streak} failures "
                            f"from the same IP, possible account takeover.",
                            _fmt(e.timestamp), _fmt(e.timestamp), 1,
                        ))
                    fail_streak = 0
        return out


def build_timeline(events, limit=None):
    tl = [{"time": _fmt(e.timestamp), "ip": e.source_ip, "user": e.user,
           "action": e.action, "detail": e.detail} for e in events]
    return tl[:limit] if limit else tl


def build_report(events, findings):
    return {
        "generated": _fmt(datetime.now()),
        "events_analysed": len(events),
        "window": {
            "from": _fmt(events[0].timestamp) if events else None,
            "to": _fmt(events[-1].timestamp) if events else None,
        },
        "top_source_ips": Counter(e.source_ip for e in events).most_common(5),
        "findings": [asdict(f) for f in findings],
    }


def _group_by_ip(events):
    g = defaultdict(list)
    for e in events:
        g[e.source_ip].append(e)
    for ip in g:
        g[ip].sort(key=lambda e: e.timestamp)
    return g


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")
