#!/usr/bin/env python3
"""Extract the SLSA provenance in-toto statement for an image digest from Rekor.

The slsa-framework container generator stores provenance in the Rekor
transparency log rather than the OCI registry. Kyverno/verifyImages can only
read OCI attestations, so the release flow re-attaches the *verified* predicate
to the image digest with cosign (keyless).

usage: rekor_provenance.py <sha256:hex-digest>
Writes only statements whose subject digest matches; errors if none found.
"""
import base64
import json
import subprocess
import sys


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def main(digest: str) -> None:
    want_algorithm, _, want_hex = digest.partition(":")

    out = subprocess.run(
        ["rekor-cli", "search", "--sha", digest, "--format", "json"],
        check=True, capture_output=True, text=True,
    ).stdout
    search = json.loads(out)
    uuids = search.get("UUIDs") or []
    if not uuids:
        sys.exit(f"no rekor entries found for {digest}")

    found = False
    for uuid in uuids:
        entry = json.loads(
            subprocess.run(
                ["rekor-cli", "get", "--uuid", uuid, "--format", "json"],
                check=True, capture_output=True, text=True,
            ).stdout
        )
        body = json.loads(b64d(entry["Body"]))
        # generator entries are hashedrekord: {"data": <b64 DSSE envelope>}
        envelope = json.loads(b64d(body["spec"]["data"]))
        if envelope.get("payloadType") != "application/vnd.in-toto+json":
            continue
        stmt = json.loads(b64d(envelope["payload"]))
        subjects = stmt.get("subject") or []
        match = any(
            d.get(want_algorithm) == want_hex
            for s in subjects
            for d in (s.get("digest") or {}).items()
        ) if False else any(
            s.get("digest", {}).get(want_algorithm) == want_hex for s in subjects
        )
        if match and stmt.get("predicateType", "").startswith("https://slsa.dev/provenance/"):
            found = True
            sys.stdout.write(json.dumps(stmt, indent=2))
            break
    if not found:
        sys.exit("no matching SLSA provenance statement in rekor entries")


if __name__ == "__main__":
    main(sys.argv[1])
