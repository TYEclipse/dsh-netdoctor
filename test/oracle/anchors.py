#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle for dsh-netdoctor expected values (R62).

Expected-value source of record for every test file that carries numeric
assertions:

  test/util.test.ts         — TCP port bounds (1 … 65535) and the exit code of a
                              successful external process (0)
  test/route.test.ts        — traceroute hop number / round-trip times parsed
                              from a unix output line (3 / 12.345)
  test/tls.test.ts          — certificate days-remaining arithmetic (10 / -10 / 0)
  test/tools.test.ts        — config defaults and overrides (3000 / 1000 / 4 / 2 / 20 / 5000)
                              plus a rendered propagation summary (3 resolvers, 2 answered)
                              and a rendered http summary (status 200, redirect 302,
                              dns 3 / connect 5 / ttfb 20 / total 30 ms, 512 body bytes)
  test/propagation.test.ts  — agreement tallies per scenario (PROPAGATION_SCENARIOS)
  test/http.test.ts         — check_http policy constants (5 redirects / 8192 body bytes /
                              200-char header cap), scheme default ports (80 / 443),
                              fixture shapes (2-hop redirect chain, 100000-byte body,
                              1024-byte read limit, 500-char header) and RFC 3986
                              redirect resolution (urljoin as the ruler)

Every number is derived here from primitives — protocol constants, datetime
arithmetic, an independent traceroute-line regex, an independent propagation
tally written from scratch (sharing no code with the TypeScript) — and printed
with a label, so each anchor can be checked against the assertion that uses it.

Usage:
  python3 test/oracle/anchors.py            # print every anchor
  python3 test/oracle/anchors.py --check    # recompute + verify (exit 1 on drift)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import socket
import subprocess
import sys
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

# ---------------------------------------------------------------------------
# Published anchors (the numbers the tests assert). `--check` recomputes each
# one from its primitives and fails if it no longer matches.
# ---------------------------------------------------------------------------
ANCHORS = {
    # TCP port space (RFC 793 / IANA service names)
    "port.min": 1,
    "port.https": 443,
    "port.max": 65535,
    # runProcess('node', ['-e', 'console.log(...)'], …) → exit code of a clean run
    "process.exit_ok": 0,
    # parseTraceLine(' 3  router.example.com (10.0.0.1)  12.345 ms')
    "trace.hop": 3,
    "trace.rtts_first": 12.345,
    # computeDaysRemaining() — whole days between two instants, plus the
    # documented 0 sentinel for an unparseable date
    "tls.days_future": 10,
    "tls.days_expired": -10,
    "tls.days_unparseable": 0,
    # resolveConfig() — schema defaults and the overrides used in tools.test.ts
    "config.timeout_ms_default": 3000,
    "config.timeout_ms_override": 1000,
    "config.ping_count_default": 4,
    "config.ping_count_override": 2,
    "config.max_hops_default": 20,
    "config.propagation_timeout_default": 5000,
    # rendered propagation summary in tools.test.ts
    "render.propagation_resolvers": 3,
    "render.propagation_answered": 2,
    "render.propagation_sets": 2,
    # built-in resolver set (parsed back out of src/propagation.ts)
    "propagation.default_resolvers": 6,
    # check_http — policy constants published by src/http.ts (read back by
    # read_ts_const, so the tests and the implementation cannot drift apart)
    "http.default_max_redirects": 5,
    "http.default_body_limit_bytes": 8192,
    "http.header_value_cap": 200,
    # check_http — protocol defaults for the two schemes
    "http.default_port_http": 80,
    "http.default_port_https": 443,
    # check_http — fixture shapes used by test/http.test.ts: the redirect route
    # the test server implements, the oversized body, the small read limit and
    # the long header value (the cap can only be observed if cap < value length)
    "http.redirect_chain_hops": 2,
    "http.body_fixture_bytes": 100000,
    "http.small_limit_bytes": 1024,
    "http.long_header_length": 500,
    "http.cookie_fixture_count": 2,
    # a 4xx must stay a reachable result, not an error
    "http.not_found_status": 404,
    # check_http — rendered summary numbers asserted in test/tools.test.ts
    "http.render_status": 200,
    "http.render_redirect_status": 302,
    "http.render_dns_ms": 3,
    "http.render_connect_ms": 5,
    "http.render_ttfb_ms": 20,
    "http.render_total_ms": 30,
    "http.render_body_bytes": 512,
    "http.render_cookie_count": 1,
}

TRACE_LINE = " 3  router.example.com (10.0.0.1)  12.345 ms"

# ---------------------------------------------------------------------------
# 1. Protocol constants
# ---------------------------------------------------------------------------


def derive_ports() -> dict[str, int]:
    return {
        "port.min": 1,  # port 0 is reserved ("this host")
        "port.https": socket.getservbyname("https", "tcp"),
        "port.max": 2**16 - 1,  # 16-bit port field
    }


def derive_exit_code() -> int:
    """Exit code of a process that runs to completion without an error."""
    proc = subprocess.run([sys.executable, "-c", "print('ok')"], capture_output=True, text=True, timeout=30)
    if proc.stdout.strip() != "ok":
        raise AssertionError("probe process did not print its marker")
    return proc.returncode


# ---------------------------------------------------------------------------
# 2. Traceroute line parsing (independent regex, not the TS implementation)
# ---------------------------------------------------------------------------

TRACE_RE = re.compile(r"^\s*(?P<hop>\d+)\s+(?P<host>\S+)\s+\((?P<addr>[^)]+)\)\s+(?P<rtt>[\d.]+)\s*ms$")


def derive_trace() -> dict[str, float | int]:
    match = TRACE_RE.match(TRACE_LINE.strip())
    if match is None:
        raise AssertionError(f"traceroute fixture is no longer parseable: {TRACE_LINE!r}")
    return {"trace.hop": int(match.group("hop")), "trace.rtts_first": float(match.group("rtt"))}


# ---------------------------------------------------------------------------
# 3. Days-remaining arithmetic
# ---------------------------------------------------------------------------


def whole_days(not_after: str, now: str) -> int:
    """Floor of the difference in whole days; the TS uses Math.floor on ms/86400000."""
    try:
        end = dt.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        start = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        return 0  # documented sentinel for an unparseable date
    delta = (end - start).total_seconds() / 86400.0
    return int(delta // 1) if delta >= 0 else -int((-delta) // 1) - (1 if (-delta) % 1 else 0)


def derive_days() -> dict[str, int]:
    now = "2026-08-14T00:00:00Z"
    future = whole_days("2026-08-24T00:00:00Z", now)
    expired = whole_days("2026-08-04T00:00:00Z", now)
    unparseable = whole_days("not a date", now)
    return {"tls.days_future": future, "tls.days_expired": expired, "tls.days_unparseable": unparseable}


# ---------------------------------------------------------------------------
# 4. Config defaults — read back from the implementation (src/index.ts)
# ---------------------------------------------------------------------------

DEFAULT_RE_TEMPLATE = r"^\s*{key}:\s*z\.[^,]*?\.default\((?P<value>[\d_]+)\)"


def read_config_default(key: str, source: Path) -> int | None:
    """Parse `key: z.<chain>.default(N)` out of the Config schema."""
    pattern = re.compile(DEFAULT_RE_TEMPLATE.format(key=re.escape(key)), re.MULTILINE)
    match = pattern.search(source.read_text(encoding="utf-8"))
    if match is None:
        return None
    return int(match.group("value").replace("_", ""))


def derive_config() -> dict[str, int]:
    source = Path("src/index.ts")
    if not source.is_file():
        raise AssertionError("src/index.ts not found — run this oracle from the repository root")
    out: dict[str, int] = {}
    for key, anchor in (
        ("timeoutMs", "config.timeout_ms_default"),
        ("pingCount", "config.ping_count_default"),
        ("maxHops", "config.max_hops_default"),
        ("propagationTimeoutMs", "config.propagation_timeout_default"),
    ):
        value = read_config_default(key, source)
        if value is None:
            raise AssertionError(f"could not read the default for config key {key!r} from src/index.ts")
        out[anchor] = value
    return out


# ---------------------------------------------------------------------------
# 5. Propagation tally — independent implementation of the agreement count
# ---------------------------------------------------------------------------


def answer(rtype: str, **data: object) -> tuple[str, dict[str, object]]:
    return (rtype, dict(data))


def canon(value: object) -> str:
    """Mirror of the TS `stableValue`: sorted object keys, JSON scalars."""
    if isinstance(value, list):
        return "[" + ",".join(canon(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(f"{key}={canon(value[key])}" for key in sorted(value)) + "}"
    return json.dumps(value, ensure_ascii=False)


def fingerprint(answers: list[tuple[str, dict[str, object]]]) -> str:
    parts = sorted(f"{rtype} {canon(data)}" for rtype, data in answers)
    return "\n".join(parts)


def tally(scenario: dict[str, object]) -> dict[str, object]:
    """Group answers per resolver exactly like dnsPropagation() does."""
    ok: list[str] = []
    failed: list[str] = []
    groups: dict[str, list[str]] = {}
    for resolver, answers in scenario["answers"].items():  # type: ignore[union-attr]
        if answers is None:  # resolver failed / timed out
            failed.append(resolver)
            continue
        ok.append(resolver)
        groups.setdefault(fingerprint(answers), []).append(resolver)  # type: ignore[arg-type]
    sizes = sorted((len(members) for members in groups.values()), reverse=True)
    responded = len(ok)
    return {
        "total": len(scenario["answers"]),  # type: ignore[arg-type]
        "responded": responded,
        "failed": len(failed),
        "groups": len(sizes),
        "group_sizes": sizes,
        "consensus": sizes[0] if sizes and sizes[0] >= 2 else None,
        "consistent": responded > 0 and len(sizes) == 1,
        "partial": 0 < len(failed),
    }


WEBDNS = [answer("A", address="93.184.216.34")]

PROPAGATION_SCENARIOS: dict[str, dict[str, object]] = {
    # every resolver returns the same address
    "agree": {
        "answers": {"1.1.1.1": WEBDNS, "8.8.8.8": WEBDNS, "9.9.9.9": WEBDNS},
    },
    # two resolvers report the old address, one the new one
    "split": {
        "answers": {
            "1.1.1.1": WEBDNS,
            "8.8.8.8": WEBDNS,
            "9.9.9.9": [answer("A", address="93.184.216.99")],
        },
    },
    # one resolver cannot be reached at all
    "failed-resolver": {
        "answers": {"1.1.1.1": WEBDNS, "8.8.8.8": WEBDNS, "9.9.9.9": None},
    },
    # one resolver hangs past the deadline, one errors, one answers
    "timeout": {
        "answers": {"1.1.1.1": WEBDNS, "8.8.8.8": None, "9.9.9.9": None},
    },
    # nobody answers
    "all-fail": {
        "answers": {"1.1.1.1": None, "8.8.8.8": None, "9.9.9.9": None},
    },
    # caller-supplied resolvers, both agreeing
    "custom": {
        "answers": {"8.8.8.8": WEBDNS, "1.1.1.1": WEBDNS},
    },
}


def derive_propagation() -> dict[str, dict[str, object]]:
    return {name: tally(scenario) for name, scenario in PROPAGATION_SCENARIOS.items()}


def propagation_invariants(tallies: dict[str, dict[str, object]]) -> list[str]:
    problems: list[str] = []
    for name, tally_result in tallies.items():
        sizes = tally_result["group_sizes"]
        if sum(sizes) != tally_result["responded"]:  # type: ignore[arg-type]
            problems.append(f"{name}: group sizes {sizes} do not sum to responded {tally_result['responded']}")
        if len(sizes) != tally_result["groups"]:  # type: ignore[arg-type]
            problems.append(f"{name}: group count mismatch")
        if tally_result["responded"] + tally_result["failed"] != tally_result["total"]:  # type: ignore[operator]
            problems.append(f"{name}: responded + failed != total")
        expected_consensus = sizes[0] if sizes and sizes[0] >= 2 else None  # type: ignore[index]
        if tally_result["consensus"] != expected_consensus:
            problems.append(f"{name}: consensus {tally_result['consensus']} != largest group {expected_consensus}")
        expected_consistent = tally_result["responded"] > 0 and len(sizes) == 1  # type: ignore[operator]
        if tally_result["consistent"] != expected_consistent:
            problems.append(f"{name}: consistent flag disagrees with the tally")
    return problems


def fingerprint_facts() -> dict[str, bool]:
    """Answer order and TTL must not change the fingerprint (caches disagree on TTL)."""
    order_a = [answer("A", address="1.1.1.1"), answer("A", address="2.2.2.2")]
    order_b = list(reversed(order_a))
    key_a = [answer("MX", exchange="mail.example.com", priority=10)]
    key_b = [answer("MX", priority=10, exchange="mail.example.com")]
    empty = fingerprint([])
    return {
        "order_insensitive": fingerprint(order_a) == fingerprint(order_b),
        "key_order_insensitive": fingerprint(key_a) == fingerprint(key_b),
        "values_matter": fingerprint(order_a) != fingerprint([answer("A", address="1.1.1.1")]),
        "empty_stable": empty == "" and fingerprint([]) == empty,
    }


# ---------------------------------------------------------------------------
# 6. check_http — policy constants (read back from src/http.ts) plus redirect
#    resolution derived with an independent RFC 3986 implementation
#    (urllib.parse.urljoin, sharing no code with the TypeScript's `new URL()`).
# ---------------------------------------------------------------------------

# The redirect route the test server implements in test/http.test.ts: each hop
# is (path, status, Location as sent). Published here so "the chain is 2 hops"
# has an authoring source instead of being a number copied into the test.
HTTP_REDIRECT_ROUTE: list[tuple[str, int, str]] = [
    ("/a", 302, "/b"),
    ("/b", 301, "c"),
]

# (base URL, Location header, the URL RFC 3986 says you end up at)
REDIRECT_JOIN_CASES: list[tuple[str, str, str]] = [
    ("http://example.com/dir/start", "../up", "http://example.com/up"),
    ("http://example.com/b", "c", "http://example.com/c"),
    ("http://example.com/a/b", "/root", "http://example.com/root"),
]


def read_ts_const(name: str, source: Path) -> int | None:
    """Read `export const <name> = <int>` out of a TypeScript source file."""
    text = source.read_text(encoding="utf-8")
    match = re.search(rf"export const {re.escape(name)}\s*=\s*([\d_]+)", text)
    if match is None:
        return None
    return int(match.group(1).replace("_", ""))


def derive_http_constants() -> dict[str, int]:
    source = Path("src/http.ts")
    if not source.is_file():
        raise AssertionError("src/http.ts not found — run this oracle from the repository root")
    out: dict[str, int] = {}
    for const, anchor in (
        ("DEFAULT_MAX_REDIRECTS", "http.default_max_redirects"),
        ("DEFAULT_BODY_LIMIT_BYTES", "http.default_body_limit_bytes"),
        ("HEADER_VALUE_CAP", "http.header_value_cap"),
    ):
        value = read_ts_const(const, source)
        if value is None:
            raise AssertionError(f"could not read {const} from src/http.ts")
        out[anchor] = value
    return out


def derive_redirect_joins() -> list[tuple[str, str, str]]:
    """Resolve every Location the way RFC 3986 does, with urljoin as the ruler."""
    return [(base, location, urljoin(base, location)) for base, location, _ in REDIRECT_JOIN_CASES]


def http_invariants() -> list[str]:
    problems: list[str] = []
    if ANCHORS["http.small_limit_bytes"] >= ANCHORS["http.body_fixture_bytes"]:
        problems.append("the body read limit must be smaller than the fixture body, or truncation is unobservable")
    if ANCHORS["http.long_header_length"] <= ANCHORS["http.header_value_cap"]:
        problems.append("the long header fixture must exceed the cap, or the cap is unobservable")
    marks = ["http.render_dns_ms", "http.render_connect_ms", "http.render_ttfb_ms", "http.render_total_ms"]
    values = [ANCHORS[key] for key in marks]
    if any(later < earlier for earlier, later in zip(values, values[1:])):
        problems.append(f"timing marks are not cumulative/monotonic: {values}")
    if ANCHORS["http.render_redirect_status"] not in (301, 302, 303, 307, 308):
        problems.append("the rendered redirect status is not a redirect status")
    if ANCHORS["http.redirect_chain_hops"] != len(HTTP_REDIRECT_ROUTE):
        problems.append("published redirect chain length disagrees with the published route table")
    return problems


# ---------------------------------------------------------------------------
# email_dns (R100): mail-readiness parsing, written from the RFC text and
# sharing no code with the TypeScript. Every number the email tests assert is
# printed here, so an expectation can never come from reading the implementation.
# ---------------------------------------------------------------------------

# RFC 7208 §4.6.4: one evaluation may cause at most 10 DNS queries.
SPF_LIMIT = 10
# RFC 7489 §6.3: pct defaults to 100 when the tag is absent.
DMARC_DEFAULT_PCT = 100
DMARC_POLICIES = ("none", "quarantine", "reject")

# Fixtures: DNS answers per case, exactly as the fake resolver in email.test.ts
# returns them.
EMAIL_CASES: dict[str, dict[str, Any]] = {
    "healthy": {
        "mx": [("mx1.mail.test", 20), ("mx2.mail.test", 10)],
        "a": ["192.0.2.10"],
        "apex_txt": [
            "v=spf1 a mx include:_spf.test ip4:192.0.2.0/24 exists:chk.test -all",
            "google-site-verification=abc",
        ],
        "dmarc_txt": ["v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@test,mailto:b@test; ruf=mailto:f@test"],
        "dkim": {"sel1": ["v=DKIM1; k=rsa; p=MIIBIjANBg"]},
    },
    "permissive": {
        "mx": [("mx1.mail.test", 10)],
        "a": ["192.0.2.10"],
        "apex_txt": [
            "v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test "
            "include:f.test include:g.test a mx ptr exists:z.test +all",
            "v=spf1 -all",
        ],
        "dmarc_txt": ["v=DMARC1; p=none; pct=100"],
        "dkim": {},
    },
    "null-mx": {
        "mx": [(".", 0)],
        "a": ["192.0.2.10"],
        "apex_txt": [],
        "dmarc_txt": [],
        "dkim": {},
    },
    "no-mx": {
        "mx": [],
        "a": ["192.0.2.11", "192.0.2.12"],
        "apex_txt": ["v=spf1 redirect=_spf.test"],
        "dmarc_txt": [],
        "dkim": {},
    },
    "odd-terms": {
        "mx": [("mx1.mail.test", 10)],
        "a": [],
        "apex_txt": ["v=spf1 mx:mail.test ?all foo:bar a:host.test/24"],
        "dmarc_txt": ["v=DMARC1; p=quarantine; p=reject"],
        "dkim": {"revoked": ["v=DKIM1; k=rsa; p="], "absent": []},
    },
    "multi-string": {
        "mx": [("mx1.mail.test", 10)],
        "a": [],
        # One TXT record whose character-strings were split at 255 bytes; the
        # fake resolver in the test hands back the two pieces separately and
        # src/email.ts must join them without a separator (RFC 7208 §3.3).
        "apex_txt": ["v=spf1 include:_spf.test -all"],
        "dmarc_txt": ["v=DMARC1;p=reject"],
        "dkim": {},
    },
    "nxdomain": {
        # Nothing resolves at all: no MX, no A/AAAA, no TXT.
        "mx": [],
        "a": [],
        "apex_txt": [],
        "dmarc_txt": [],
        "dkim": {},
    },
}

EMAIL_DKIM_SELECTORS = {
    "healthy": ["sel1"],
    "permissive": [],
    "null-mx": [],
    "no-mx": [],
    "odd-terms": ["revoked", "absent"],
    "multi-string": [],
    "nxdomain": [],
}


def spf_mechanisms(record: str) -> list[str]:
    """Split an SPF record into terms, asserting the version tag is first (RFC 7208 §4.5)."""
    tokens = record.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        raise AssertionError(f"not an SPF record: {record!r}")
    return tokens[1:]


def classify_spf_term(term: str) -> tuple[str, int, bool]:
    """Return (kind, dns_lookups_caused, is_unknown) for one SPF term."""
    body = term.lstrip("+-~?")
    if body == "" or body == "all":
        return ("all", 0, False)
    if body.startswith("ip4:") or body.startswith("ip6:"):
        return ("ip", 0, False)
    if "=" in body:
        key = body.split("=", 1)[0].lower()
        if key == "redirect":
            return ("redirect", 1, False)
        if key == "exp":
            return ("exp", 0, False)
        return ("modifier", 0, False)
    head = re.split(r"[:/]", body)[0]
    if head in ("include", "exists", "a", "mx", "ptr"):
        return (head, 1, False)
    return ("unknown", 0, True)


def parse_spf(record: str) -> dict[str, object]:
    terms = spf_mechanisms(record)
    lookups = 0
    includes: list[str] = []
    unknown: list[str] = []
    redirect = None
    all_index = -1
    all_qualifier = None
    for index, term in enumerate(terms):
        kind, caused, is_unknown = classify_spf_term(term)
        lookups += caused
        if is_unknown:
            unknown.append(term)
        body = term.lstrip("+-~?")
        if body == "all":
            if all_index < 0:
                all_index = index
                all_qualifier = term[0] if term[0] in "+-~?" else "+"
            continue
        if body.lower().startswith("include:"):
            includes.append(body.split(":", 1)[1])
        if body.lower().startswith("redirect="):
            redirect = body.split("=", 1)[1]
    return {
        "terms": len(terms),
        "lookups": lookups,
        "all_qualifier": all_qualifier,
        "all_last": all_index >= 0 and all_index == len(terms) - 1,
        "includes": includes,
        "redirect": redirect,
        "unknown": unknown,
        "exceeds": lookups > SPF_LIMIT,
    }


def parse_dmarc(record: str) -> dict[str, object]:
    tags: dict[str, str] = {}
    order: list[str] = []
    duplicates: list[str] = []
    for segment in record.split(";"):
        part = segment.strip()
        if part == "" or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "":
            continue
        if key in tags:
            duplicates.append(key)
            continue
        tags[key] = value
        order.append(key)
    version_first = bool(order) and order[0] == "v" and tags.get("v", "").lower() == "dmarc1"
    return {"tags": tags, "order": order, "version_first": version_first, "duplicates": duplicates}


def sort_mx(records: list[tuple[str, int]]) -> list[str]:
    """MX order is by ascending priority, ties broken by exchange (deterministic)."""
    return [f"{priority}:{exchange}" for exchange, priority in sorted(records, key=lambda item: (item[1], item[0]))]


def email_findings(case: dict[str, Any], selectors: list[str]) -> list[str]:
    """Reproduce the finding pipeline of src/email.ts from the parsed facts."""
    found: list[tuple[int, str]] = []

    def add(severity: int, code: str) -> None:
        found.append((severity, code))

    mx_records = [(str(exchange), int(priority)) for exchange, priority in case["mx"]]
    apex = [str(record) for record in case["apex_txt"]]
    dmarc_records = [str(record) for record in case["dmarc_txt"]]
    spf_records = [record for record in apex if record.lower().startswith("v=spf1")]
    null_mx = len(mx_records) == 1 and mx_records[0][1] == 0 and mx_records[0][0] in (".", "")

    if null_mx:
        add(2, "mx-null")
    elif len(mx_records) == 0:
        # No MX and no address to fall back to: the name itself does not
        # resolve, which is a different diagnosis from "MX is unset".
        if len(case["a"]) == 0:
            add(0, "domain-not-found")
        else:
            add(1, "mx-missing")

    if spf_records:
        spf = parse_spf(spf_records[0])
        if len(spf_records) > 1:
            add(0, "spf-multiple")
        if spf["exceeds"]:
            add(1, "spf-too-many-lookups")
        if spf["all_qualifier"] is None:
            add(2, "spf-no-all")
        else:
            if spf["all_qualifier"] in ("+", "?"):
                add(1, "spf-permissive")
            if not spf["all_last"]:
                add(1, "spf-all-not-last")
        if spf["unknown"]:
            add(1, "spf-unknown-term")
    else:
        add(1, "spf-missing")

    if dmarc_records:
        dmarc = parse_dmarc(dmarc_records[0])
        tags = dmarc["tags"]
        if len(dmarc_records) > 1:
            add(0, "dmarc-multiple")
        if not dmarc["version_first"]:
            add(1, "dmarc-version-not-first")
        policy = tags.get("p")
        if policy is None:
            add(0, "dmarc-policy-missing")
        elif policy not in DMARC_POLICIES:
            add(0, "dmarc-policy-invalid")
        elif policy == "none":
            add(2, "dmarc-policy-none")
        pct = tags.get("pct")
        if pct is not None and pct.isdigit() and int(pct) < DMARC_DEFAULT_PCT:
            add(2, "dmarc-pct-partial")
    else:
        add(1, "dmarc-missing")

    for selector in selectors:
        records = [str(item) for item in (case.get("dkim") or {}).get(selector, [])]  # type: ignore[union-attr]
        key_record = next((record for record in records if re.search(r"(?:^|;)\s*p\s*=", record, re.I)), None)
        if key_record is None:
            add(1, "dkim-missing")
            continue
        key_tags = {k.strip().lower(): v.strip() for k, _, v in (part.partition("=") for part in key_record.split(";") if "=" in part)}
        if key_tags.get("p", "") == "":
            add(1, "dkim-revoked")
    if not selectors:
        add(2, "dkim-not-checked")

    return [code for _severity, code in sorted(found, key=lambda item: item[0])]


def email_facts(case_name: str) -> dict[str, Any]:
    case = EMAIL_CASES[case_name]
    selectors = EMAIL_DKIM_SELECTORS[case_name]
    mx_records = [(str(exchange), int(priority)) for exchange, priority in case["mx"]]
    apex = [str(record) for record in case["apex_txt"]]
    dmarc_records = [str(record) for record in case["dmarc_txt"]]
    spf_records = [record for record in apex if record.strip().lower().startswith("v=spf1")]
    null_mx = len(mx_records) == 1 and mx_records[0][1] == 0 and mx_records[0][0] in (".", "")

    facts: dict[str, Any] = {
        "mx_order": sort_mx(mx_records),
        "null_mx": null_mx,
        "implicit_mx": len(mx_records) == 0 and not null_mx,
        "mail_accepted": (not null_mx) and (len(mx_records) > 0 or len(case["a"]) > 0),
        "spf_records": len(spf_records),
        "findings": email_findings(case, selectors),
    }
    if spf_records:
        spf = parse_spf(spf_records[0])
        facts["spf_terms"] = spf["terms"]
        facts["spf_lookups"] = spf["lookups"]
        facts["spf_all_qualifier"] = spf["all_qualifier"]
        facts["spf_all_last"] = spf["all_last"]
        facts["spf_includes"] = spf["includes"]
        facts["spf_redirect"] = spf["redirect"]
        facts["spf_unknown"] = spf["unknown"]
        facts["spf_exceeds"] = spf["exceeds"]
    if dmarc_records:
        dmarc = parse_dmarc(dmarc_records[0])
        tags = dmarc["tags"]
        facts["dmarc_policy"] = tags.get("p")
        facts["dmarc_sp"] = tags.get("sp")
        facts["dmarc_pct"] = int(tags["pct"]) if tags.get("pct", "").isdigit() else None
        facts["dmarc_rua"] = len([uri for uri in tags.get("rua", "").split(",") if uri.strip()])
        facts["dmarc_ruf"] = len([uri for uri in tags.get("ruf", "").split(",") if uri.strip()])
        facts["dmarc_version_first"] = dmarc["version_first"]
        facts["dmarc_duplicates"] = dmarc["duplicates"]
    facts["dkim"] = [
        {
            "selector": selector,
            "found": any(re.search(r"(?:^|;)\s*p\s*=", str(record), re.I) for record in (case.get("dkim") or {}).get(selector, [])),
        }
        for selector in selectors
    ]
    return facts


def email_invariants() -> list[str]:
    """Facts that must hold no matter which fixture is looked at."""
    problems: list[str] = []
    if SPF_LIMIT != 10:
        problems.append("the SPF DNS-lookup limit is 10 (RFC 7208 §4.6.4)")
    if DMARC_DEFAULT_PCT != 100:
        problems.append("the DMARC pct default is 100 (RFC 7489 §6.3)")
    # include/a/mx/ptr/exists and redirect= are the only DNS-querying terms.
    for term, expected in (
        ("include:x.test", 1), ("exists:x.test", 1), ("a", 1), ("a:x.test/24", 1), ("mx", 1),
        ("mx:x.test", 1), ("ptr", 1), ("ptr:x.test", 1), ("redirect=x.test", 1),
        ("ip4:192.0.2.1", 0), ("ip6:2001:db8::1", 0), ("all", 0), ("-all", 0), ("exp=x.test", 0),
    ):
        kind, caused, unknown = classify_spf_term(term)
        if caused != expected:
            problems.append(f"spf term {term!r} classified as {kind} with {caused} lookup(s), expected {expected}")
        if unknown:
            problems.append(f"spf term {term!r} was classified as unknown")
    # Unknown mechanisms must be flagged rather than silently ignored.
    if not classify_spf_term("foo:bar")[2]:
        problems.append("an unrecognised SPF term must be reported as unknown")
    # Version-first is a position rule, not a substring rule (RFC 7489 §6.6.1).
    if parse_dmarc("p=reject; v=DMARC1")["version_first"]:
        problems.append("a DMARC record whose v tag is not first must not count as version-first")
    if not parse_dmarc("v=DMARC1; p=reject")["version_first"]:
        problems.append("a DMARC record starting with v=DMARC1 must count as version-first")
    # Null MX is exactly one "0 ." record (RFC 7505).
    for records, expected in (
        ([(".", 0)], True),
        ([(".", 10)], False),
        ([(".", 0), ("mx.test", 10)], False),
        ([], False),
    ):
        actual = len(records) == 1 and records[0][1] == 0 and records[0][0] == "."
        if actual != expected:
            problems.append(f"null-MX detection for {records!r} gave {actual}, expected {expected}")
    return problems


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def derive_default_resolvers() -> int:
    """Count the built-in resolver list in src/propagation.ts (independent read)."""
    source = Path("src/propagation.ts")
    if not source.is_file():
        raise AssertionError("src/propagation.ts not found — run this oracle from the repository root")
    text = source.read_text(encoding="utf-8")
    start = text.find("DEFAULT_RESOLVERS")
    if start < 0:
        raise AssertionError("DEFAULT_RESOLVERS not found in src/propagation.ts")
    open_bracket = text.find("= [", start)
    if open_bracket < 0:
        raise AssertionError("the DEFAULT_RESOLVERS array literal was not found in src/propagation.ts")
    end = text.find("]", open_bracket)
    block = text[open_bracket:end]
    return len(re.findall(r"\{\s*label:\s*'", block))


def render(checks: list[str] | None = None, total: int = 0) -> str:
    lines: list[str] = []
    for key in sorted(ANCHORS):
        lines.append(f"  {key:<36} = {ANCHORS[key]}")
    lines.append("")
    lines.append("[propagation scenarios] (total/responded/failed/groups/group_sizes/consensus/consistent/partial)")
    for name, tally_result in derive_propagation().items():
        lines.append(
            f"  {name:<16} total={tally_result['total']} responded={tally_result['responded']} "
            f"failed={tally_result['failed']} groups={tally_result['groups']} "
            f"sizes={tally_result['group_sizes']} consensus={tally_result['consensus']} "
            f"consistent={tally_result['consistent']} partial={tally_result['partial']}"
        )
    lines.append("")
    lines.append("[fingerprint facts] " + json.dumps(fingerprint_facts(), sort_keys=True))
    lines.append("")
    lines.append("[check_http] redirect route + RFC 3986 resolution (urljoin as the ruler)")
    for path, status, location in HTTP_REDIRECT_ROUTE:
        lines.append(f"  route {path:<12} {status} Location: {location!r}")
    for base, location, resolved in derive_redirect_joins():
        lines.append(f"  {base} + {location!r} → {resolved}")
    lines.append("")
    lines.append("[email_dns] mail readiness per fixture (mx order / null / implicit / accepted / spf / dmarc / findings)")
    for case_name in EMAIL_CASES:
        facts = email_facts(case_name)
        lines.append(
            f"  {case_name:<13} mx={facts['mx_order']} null={facts['null_mx']} implicit={facts['implicit_mx']} "
            f"accepted={facts['mail_accepted']} spf_records={facts['spf_records']} terms={facts.get('spf_terms')} "
            f"lookups={facts.get('spf_lookups')} all={facts.get('spf_all_qualifier')} all_last={facts.get('spf_all_last')} "
            f"includes={facts.get('spf_includes')} redirect={facts.get('spf_redirect')} unknown={facts.get('spf_unknown')} "
            f"exceeds={facts.get('spf_exceeds')}"
        )
        if "dmarc_policy" in facts:
            lines.append(
                f"                dmarc p={facts['dmarc_policy']} sp={facts['dmarc_sp']} pct={facts['dmarc_pct']} "
                f"rua={facts['dmarc_rua']} ruf={facts['dmarc_ruf']} version_first={facts['dmarc_version_first']} "
                f"duplicates={facts['dmarc_duplicates']}"
            )
        lines.append(f"                dkim={facts['dkim']}")
        lines.append(f"                findings={facts['findings']}")
    if checks is not None:
        lines.append("")
        lines.append(f"[--check] {total} verification(s): " + ("ALL PASS" if not checks else f"{len(checks)} FAILURE(S)"))
        for problem in checks:
            lines.append(f"  ✗ {problem}")
    return "\n".join(lines)


def run_checks() -> tuple[int, list[str]]:
    problems: list[str] = []
    total = 0

    def expect(label: str, actual: object, expected: object) -> None:
        nonlocal total
        total += 1
        if actual != expected:
            problems.append(f"{label}: recomputed {actual!r} != published {expected!r}")

    for key, value in derive_ports().items():
        expect(key, value, ANCHORS[key])
    expect("port.max (16-bit field)", 2**16 - 1, ANCHORS["port.max"])
    expect("https service name", socket.getservbyname("https", "tcp"), ANCHORS["port.https"])
    expect("process.exit_ok", derive_exit_code(), ANCHORS["process.exit_ok"])
    for key, value in derive_trace().items():
        expect(key, value, ANCHORS[key])
    if ANCHORS["trace.hop"] < 1:
        problems.append("trace.hop must be a positive hop index")
    for key, value in derive_days().items():
        expect(key, value, ANCHORS[key])
    if ANCHORS["tls.days_future"] != -ANCHORS["tls.days_expired"]:
        problems.append("tls days anchors are no longer symmetric around the reference instant")
    for key, value in derive_config().items():
        expect(key, value, ANCHORS[key])
    if ANCHORS["config.timeout_ms_override"] >= ANCHORS["config.timeout_ms_default"]:
        problems.append("the override anchor must be smaller than the default it overrides")
    expect("propagation.default_resolvers", derive_default_resolvers(), ANCHORS["propagation.default_resolvers"])
    if ANCHORS["propagation.default_resolvers"] <= ANCHORS["render.propagation_resolvers"]:
        problems.append("the built-in resolver set must be larger than the 3-resolver scenario used in the render test")

    tallies = derive_propagation()
    problems.extend(propagation_invariants(tallies))
    expect("propagation/agree responded", tallies["agree"]["responded"], 3)
    expect("propagation/agree consistent", tallies["agree"]["consistent"], True)
    expect("propagation/split group_sizes", tallies["split"]["group_sizes"], [2, 1])
    expect("propagation/split consensus", tallies["split"]["consensus"], 2)
    expect("propagation/failed-resolver failed", tallies["failed-resolver"]["failed"], 1)
    expect("propagation/timeout responded", tallies["timeout"]["responded"], 1)
    expect("propagation/timeout failed", tallies["timeout"]["failed"], 2)
    expect("propagation/all-fail responded", tallies["all-fail"]["responded"], 0)
    expect("propagation/all-fail groups", tallies["all-fail"]["groups"], 0)
    expect("propagation/custom total", tallies["custom"]["total"], 2)

    for name, fact in fingerprint_facts().items():
        total += 1
        if not fact:
            problems.append(f"fingerprint fact {name} is false")

    # ---- check_http ------------------------------------------------------
    for key, value in derive_http_constants().items():
        expect(key, value, ANCHORS[key])
    expect("http.default_port_http", socket.getservbyname("http", "tcp"), ANCHORS["http.default_port_http"])
    expect("http.default_port_https", socket.getservbyname("https", "tcp"), ANCHORS["http.default_port_https"])
    expect("http.not_found_status", HTTPStatus.NOT_FOUND.value, ANCHORS["http.not_found_status"])
    for base, location, resolved in derive_redirect_joins():
        expect(f"redirect {base!r} + {location!r}", resolved, next(published for b, l, published in REDIRECT_JOIN_CASES if b == base and l == location))
    problems.extend(http_invariants())
    problems.extend(email_invariants())
    # The two fixtures that carry the interesting SPF facts must actually
    # produce them — a green check over fixtures that silently parse nothing
    # would be the same false pass this oracle exists to prevent.
    healthy = email_facts("healthy")
    expect("email/healthy lookups", healthy["spf_lookups"], 4)
    expect("email/healthy all", healthy["spf_all_qualifier"], "-")
    expect("email/healthy findings", healthy["findings"], ["dmarc-pct-partial"])
    permissive = email_facts("permissive")
    expect("email/permissive lookups", permissive["spf_lookups"], 11)
    expect("email/permissive exceeds", permissive["spf_exceeds"], True)
    expect("email/permissive findings", permissive["findings"], ["spf-multiple", "spf-too-many-lookups", "spf-permissive", "dmarc-policy-none", "dkim-not-checked"])
    # A name that resolves to nothing at all is a different diagnosis from an
    # unset MX, so the fixture set must keep both outcomes apart.
    expect("email/nxdomain findings", email_facts("nxdomain")["findings"], ["domain-not-found", "spf-missing", "dmarc-missing", "dkim-not-checked"])
    expect("email/no-mx accepts mail", email_facts("no-mx")["mail_accepted"], True)
    expect("email/null-mx refuses mail", email_facts("null-mx")["mail_accepted"], False)
    return total, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Oracle for dsh-netdoctor expected values")
    parser.add_argument("--check", action="store_true", help="recompute every anchor and verify it")
    args = parser.parse_args(argv)

    checks: list[str] | None = None
    total = 0
    if args.check:
        total, checks = run_checks()
    print(render(checks, total))
    if checks:
        for problem in checks:
            print(f"ORACLE CHECK FAILED: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
