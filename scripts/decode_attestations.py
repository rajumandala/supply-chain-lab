#!/usr/bin/env python3
"""Parse `cosign verify-attestation --output json` output and decode payloads.

usage: decode_attestations.py <output-file> <predicate-type> > decoded.json
decoded.json: list of in-toto statements (already verified by cosign).
"""
import base64
import json
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_text().strip()
ptype = sys.argv[2]

stmts = []
if raw:
    for line in raw.splitlines():  # `cosign verify-attestation` prints JSON objects per line
        line = line.strip()
        if not line.startswith("{"):
            continue
        obj = json.loads(line)
        for envelope in (obj if isinstance(obj, list) else [obj]):
            try:
                payload = envelope.get("payload") or envelope.get("Payload")
                if payload is None:
                    continue
                stmt = json.loads(base64.b64decode(payload))
            except Exception:
                continue
            if stmt.get("predicateType") == ptype:
                stmts.append(stmt)

for s in stmts:
    sys.stdout.write(json.dumps(s) + "\n")
