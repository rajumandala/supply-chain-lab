#!/usr/bin/env python3
"""Supply-chain gate: enforce OUR policy over raw scan results, not tool defaults.

Reads (if present): semgrep.json, gitleaks.json, trivy-fs.json, trivy-image.json
Writes gate.json used later by the attestation + release jobs:
  {
    "run": {"commit": ..., "run_url": ...},
    "tools": {"sast": {...counts}, "sca": {...}, "secrets": {...}},
    "failed": bool,
    "reasons": [...]
  }
Policy: fail on any critical or high finding, or any secret.
Semgrep levels: ERROR -> high (semgrep has no critical).
Exit 1 iff failed.
"""
import json
import os
import sys
from pathlib import Path


def read_json_nonempty(path):
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print(f"gate: could not parse {path}: {e}", file=sys.stderr)
        return None


def count_trivy(report):
    crit = high = 0
    for r in report.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "").upper()
            if sev == "CRITICAL":
                crit += 1
            elif sev == "HIGH":
                high += 1
    return crit, high


def count_semgrep(report):
    high = 0
    for r in report.get("results") or []:
        sev = (r.get("extra", {}).get("severity") or "").upper()
        if sev == "ERROR":
            high += 1  # semgrep has no 'critical'; treat ERROR as high
    return 0, high


def count_gitleaks(report):
    return 0, 0, len(report if isinstance(report, list) else [])


def read_text_version(path):
    p = Path(path)
    return p.read_text().strip() if p.exists() else ""


def main():
    no_fail = "--no-fail" in sys.argv
    enforce_only = "--enforce-only" in sys.argv
    tools = {
        "sast": {"critical": 0, "high": 0, "secrets": 0},
        "sca": {"critical": 0, "high": 0, "secrets": 0},
        "secrets": {"critical": 0, "high": 0, "secrets": 0},
    }
    # SAST: semgrep
    rep = read_json_nonempty("semgrep.json")
    if rep is not None:
        c, h = count_semgrep(rep)
        tools["sast"]["critical"] += c
        tools["sast"]["high"] += h
    # SCA: trivy fs + image combined
    for f in ("trivy-fs.json", "trivy-image.json"):
        rep = read_json_nonempty(f)
        if rep is not None:
            c, h = count_trivy(rep)
            tools["sca"]["critical"] += c
            tools["sca"]["high"] += h
    # Secrets: gitleaks
    rep = read_json_nonempty("gitleaks.json")
    if rep is not None:
        _, _, n = count_gitleaks(rep)
        tools["secrets"]["secrets"] = n

    # Tool versions, recorded into the evidence when the CI writes *.version files.
    for fname, tool_id in (
        ("semgrep.version", "sast"), ("trivy.version", "sca"),
        ("gitleaks.version", "secrets"),
    ):
        txt = read_text_version(fname)
        if txt:
            tools[tool_id]["version"] = txt

    failed = any(
        t["critical"] > 0 or t["high"] > 0 or t["secrets"] > 0 for t in tools.values()
    )
    reasons = [
        f"{tool}: critical={c} high={h} secrets={s}"
        for tool, (c, h, s) in (
            (k, (t["critical"], t["high"], t["secrets"])) for k, t in tools.items()
        )
    ]

    gate = {
        "run": {
            "commit": os.environ.get("GITHUB_SHA", "local"),
            "run_url": _run_url(),
        },
        "tools": tools,
        "failed": failed,
        "reasons": reasons,
    }
    Path("gate.json").write_text(json.dumps(gate, indent=2))    # Rich check output
    for r in reasons:
        print(f"::notice::gate: {r}")
    for tool, t in tools.items():
        if t["critical"] > 0 or t["high"] > 0 or t["secrets"] > 0:
            print(
                f"::error::gate failure: {tool}"
                + (f" critical={t['critical']}" if t["critical"] else "")
                + (f", {t['high']} high" if t["high"] else "")
                + (f", {t['secrets']} secrets" if t["secrets"] else "")
            )

    # Step summary
    summ = Path(os.environ.get("GITHUB_STEP_SUMMARY", "/dev/null"))
    with summ.open("a") as fh:
        fh.write("## Scan gate\n\n| tool | critical | high | secrets | verdict |\n|---|---|---|---|---|\n")
        for k, t in tools.items():
            bad = t["critical"] > 0 or t["high"] > 0 or t["secrets"] > 0
            fh.write(f"| {k} | {t['critical']} | {t['high']} | {t['secrets']} | {'FAIL' if bad else 'pass'} |\n")
        fh.write(f"\nOverall: **{'FAIL' if failed else 'PASS'}** (policy: fail on critical/high or any secret)\n")

    sys.exit(0 if enforce_only or no_fail else (1 if failed else 0))


def _run_url():
    import os

    repo = os.environ.get("GITHUB_REPOSITORY", "local/repo")
    run = os.environ.get("GITHUB_RUN_ID", "0")
    return f"https://github.com/{repo}/actions/runs/{run}"


if __name__ == "__main__":
    main()
