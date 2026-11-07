#!/usr/bin/env python3
"""Emit an in-toto predicate JSON for one scan tool, bound to the current run.

usage: write_predicate.py <tool> <gate_path>
predicate shape (wrapped by cosign into a DSSE in-toto statement):
  {"tool", "tool_version", "commit", "run_url", "source", "findings": {critical, high, secrets}}
"""
import json
import sys
from pathlib import Path

tool, gate_path = sys.argv[1], sys.argv[2]
gate = json.loads(Path(gate_path).read_text())

predicate = {
    "tool": tool,
    "tool_version": gate["tools"].get(tool, {}).get("version", "unrecorded"),
    "commit": gate["run"]["commit"],
    "run_url": gate["run"]["run_url"],
    "source": "github.com/rajumandala/supply-chain-lab",
    "findings": {
        k: gate["tools"].get(tool, {}).get(k, 0)
        for k in ("critical", "high", "secrets")
    },
}
sys.stdout.write(json.dumps(predicate, indent=2))
