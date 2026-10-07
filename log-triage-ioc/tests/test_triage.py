import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.triage import parse_logs, Detector, build_report


AUTH = [
    "2026-08-14 09:03:44 auth FAILURE user=admin ip=203.0.113.66",
    "2026-08-14 09:03:46 auth FAILURE user=admin ip=203.0.113.66",
    "2026-08-14 09:03:48 auth FAILURE user=admin ip=203.0.113.66",
    "2026-08-14 09:03:50 auth FAILURE user=admin ip=203.0.113.66",
    "2026-08-14 09:03:52 auth FAILURE user=admin ip=203.0.113.66",
    "2026-08-14 09:03:58 auth SUCCESS user=admin ip=203.0.113.66",
    "2026-08-14 09:01:12 auth SUCCESS user=alice ip=10.0.0.5",
]


def cats(findings):
    return {f.category for f in findings}


def test_parses_auth_and_http():
    lines = AUTH + ['45.61.99.10 [14/Aug/2026:09:15:30] "GET /x HTTP/1.1" 200']
    events = parse_logs(lines)
    assert len(events) == len(lines)
    assert any(e.action == "http_request" for e in events)


def test_events_are_time_sorted():
    events = parse_logs(AUTH)
    ts = [e.timestamp for e in events]
    assert ts == sorted(ts)


def test_brute_force_detected():
    findings = Detector(bruteforce_threshold=5).run(parse_logs(AUTH))
    assert "brute_force" in cats(findings)


def test_account_takeover_detected():
    findings = Detector(bruteforce_threshold=5).run(parse_logs(AUTH))
    assert "likely_account_takeover" in cats(findings)


def test_credential_stuffing_detected():
    stuffing = [
        f"2026-08-14 09:10:0{i} auth FAILURE user=user{i} ip=198.51.100.23"
        for i in range(6)
    ]
    findings = Detector(bruteforce_threshold=5).run(parse_logs(stuffing))
    assert "credential_stuffing" in cats(findings)


def test_known_bad_ip_flagged():
    lines = ['45.61.99.10 [14/Aug/2026:09:15:30] "GET /admin HTTP/1.1" 200']
    findings = Detector(ioc_ips=["45.61.99.10"]).run(parse_logs(lines))
    assert "known_bad_ip" in cats(findings)


def test_clean_logs_produce_no_findings():
    clean = ["2026-08-14 09:01:12 auth SUCCESS user=alice ip=10.0.0.5"]
    findings = Detector(ioc_ips=["1.2.3.4"]).run(parse_logs(clean))
    assert findings == []


def test_report_has_window_and_counts():
    events = parse_logs(AUTH)
    report = build_report(events, [])
    assert report["events_analysed"] == len(events)
    assert report["window"]["from"] <= report["window"]["to"]


def test_findings_sorted_high_first():
    events = parse_logs(AUTH)
    findings = Detector(ioc_ips=["203.0.113.66"]).run(events)
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key={"high": 0, "medium": 1, "low": 2}.get)
