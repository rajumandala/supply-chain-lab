#!/usr/bin/env python3
"""Assemble the release evidence bundle from verified attestations only.

usage: build_evidence.py prov_verified(0/1) <prov_att.json-ish stmts file> <scans_stmts file> <changed_paths file>

The `changed_paths file` contains one path per line (empty file = none).
Writes evidence.json on stdout in the shape policy/release.rego expects.
"""
import json
import sys
from pathlib import Path

prov_verified = sys.argv[1] == "1"
prov_stmts_path, scans_stmts_path, changed_paths_path = sys.argv[2:5]

scans = {
    "sast": {"tool": "sast", "verified": False, "critical": 0, "high": 0, "secrets": 0},
    "sca": {"tool": "sca", "verified": False, "critical": 0, "high": 0, "secrets": 0},
    "secrets": {"tool": "secrets", "verified": False, "critical": 0, "high": 0, "secrets": 0},
}

# From verified *scan* statements (each was cosign-verified, else not listed here)
for line in Path(scans_stmts_path).read_text().splitlines():
    if not line.strip():
        continue
    stmt = json.loads(line)
    p = stmt.get("predicate", {})
    tool = p.get("tool")
    if tool in scans:
        scans[tool].update(
            verified=True,
            critical=int(p.get("findings", {}).get("critical", 0)),
            high=int(p.get("findings", {}).get("high", 0)),
            secrets=int(p.get("findings", {}).get("secrets", 0)),
        )

# From the verified *provenance* statement (our OCI re-attachment)
prov = {"verified": False, "builder_id": "", "source": ""}
for line in Path(prov_stmts_path).read_text().splitlines():
    if not line.strip():
        continue
    stmt = json.loads(line)
    pred = stmt.get("predicate", {})
    prov["builder_id"] = (pred.get("builder") or {}).get("id", "")
    prov["source"] = (pred.get("invocation") or {}).get("configSource", {}).get("uri", "")
    if prov_verified:
        prov["verified"] = True

changed = [
    l.strip()
    for l in Path(changed_paths_path).read_text().splitlines()
    if l.strip()
]

evidence = {
    "provenance": prov,
    "scans": sorted(scans.values(), key=lambda s: s["tool"]),
    "changed_paths": changed,
}
json.dump(evidence, sys.stdout, indent=2)
