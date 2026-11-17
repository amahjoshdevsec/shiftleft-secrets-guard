#!/usr/bin/env python3
"""
Turn the secret_guard audit log into the numbers leadership asks for.

The question is not "how many findings" but "how far did each secret get".
A secret stopped at the prompt, in an agent action or at pre-commit costs nothing.
A secret that reaches CI is on the remote: treat it as exposed and rotate it.
The goal is to push the distribution left over time.

Each unique secret (by fingerprint) is counted once, at the furthest point it reached.

  python3 metrics/report.py [AUDIT_LOG] [--json] [--since DAYS]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections import Counter
from pathlib import Path

STAGES = ["prompt", "tool", "precommit", "ci"]
LABEL = {"prompt": "AI prompt (IDE)", "tool": "AI agent action (IDE)",
         "precommit": "pre-commit (laptop)", "ci": "CI (remote)"}
ON_LAPTOP = {"prompt", "tool", "precommit"}
LEGACY = {"scan": "precommit"}
POLICY_RULES = {"sensitive-file-access", "env-dump", "hook-bypass", "guard-tamper", "guard-error"}


def load(path: Path, since_days: int | None = None) -> list[dict]:
    cutoff = None
    if since_days is not None:
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=since_days)
    recs = []
    for ln in path.read_text().splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        r["event"] = LEGACY.get(r.get("event"), r.get("event"))
        if r.get("event") not in STAGES:
            continue
        if cutoff and dt.datetime.fromisoformat(r["ts"]) < cutoff:
            continue
        recs.append(r)
    return recs


def summarize(recs: list[dict]) -> dict:
    secrets = [r for r in recs if r.get("rule_id") not in POLICY_RULES]
    policy = [r for r in recs if r.get("rule_id") in POLICY_RULES]
    furthest: dict[str, int] = {}
    for r in secrets:
        i = STAGES.index(r["event"])
        furthest[r["fingerprint"]] = max(furthest.get(r["fingerprint"], -1), i)
    reached = Counter(STAGES[i] for i in furthest.values())
    unique = len(furthest)
    stopped = sum(reached[s] for s in ON_LAPTOP)
    return {
        "detections_by_stage": {s: sum(1 for r in secrets if r["event"] == s) for s in STAGES},
        "unique_secrets_by_furthest_stage": {s: reached[s] for s in STAGES},
        "unique_secrets": unique,
        "stopped_on_laptop": stopped,
        "stopped_on_laptop_pct": round(100 * stopped / unique) if unique else None,
        "reached_ci": reached["ci"],
        "agent_policy_blocks": dict(Counter(r["rule_id"] for r in policy).most_common()),
        "top_rules": dict(Counter(r["rule_id"] for r in secrets).most_common(5)),
        "by_repo": dict(Counter(r.get("repo", "?") for r in secrets).most_common(5)),
    }


def render(s: dict) -> str:
    out = [f"{'Secret detections by enforcement point':<40}{'events':>7}{'unique*':>9}"]
    for st in STAGES:
        out.append(f"  {LABEL[st]:<38}{s['detections_by_stage'][st]:>7}"
                   f"{s['unique_secrets_by_furthest_stage'][st]:>9}")
    out.append("  * each unique secret counted once, at the furthest point it reached")
    out.append("")
    out.append(f"Unique secrets:                     {s['unique_secrets']}")
    if s["unique_secrets"]:
        out.append(f"Stopped on the laptop:              {s['stopped_on_laptop']} of {s['unique_secrets']}"
                   f" ({s['stopped_on_laptop_pct']}%)  <- the shift-left number")
        out.append(f"Reached CI (treat as exposed):      {s['reached_ci']}  <- each one needs rotation")
    if s["agent_policy_blocks"]:
        out.append("")
        out.append("Agent actions blocked by policy")
        for rule, n in s["agent_policy_blocks"].items():
            out.append(f"  {rule:<38}{n:>7}")
    if s["top_rules"]:
        out.append("")
        out.append("Top rules")
        for rule, n in s["top_rules"].items():
            out.append(f"  {rule:<38}{n:>7}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    default = os.environ.get("GUARD_AUDIT_LOG", str(Path.home() / ".secret_guard" / "audit.jsonl"))
    ap = argparse.ArgumentParser(description="Where are we catching secrets?")
    ap.add_argument("path", nargs="?", default=default)
    ap.add_argument("--json", action="store_true", help="machine-readable output for a dashboard")
    ap.add_argument("--since", type=int, metavar="DAYS")
    a = ap.parse_args(argv)
    p = Path(a.path)
    if not p.exists():
        print(f"no audit log at {p}", file=sys.stderr)
        return 1
    s = summarize(load(p, a.since))
    print(json.dumps(s, indent=2) if a.json else render(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
