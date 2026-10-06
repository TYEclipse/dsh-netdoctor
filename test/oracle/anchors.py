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
  test/propagation.test.ts  — agreement tallies per scenario (PROPAGATION_SCENARIOS)

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
from pathlib import Path

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
