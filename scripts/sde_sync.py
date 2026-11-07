#!/usr/bin/env python3
"""Update mock SD Elements countermeasures for a release decision.

Called by release.yml sde_update jobs. Requires:
  env: MOCK_BASE_URL, SDE_TOKEN (ci token), CR_TOKEN, EVIDENCE (path),
       DECISION, RUN_URL, CR_ID (optional; sets approved digest note)
Register the verified-attestation ledger FIRST (only types that came from
cosign-verified statements), then set Complete/Incomplete per check, then
reconcile: anything that claims Complete without a matching verified
attestation is reverted by the mock and logged as an alert.
"""
import json
import os
import sys
from pathlib import Path

import urllib.request


def api(method, path, body=None, token=None):
    req = urllib.request.Request(
        os.environ["MOCK_BASE_URL"].rstrip("/") + path,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}" if token else "",
        },
        data=json.dumps(body).encode() if body is not None else None,
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def main():
    base = os.environ["MOCK_BASE_URL"].rstrip("/")
    evidence_path = os.environ["EVIDENCE"]
    decision = os.environ["DECISION"]
    run_url = os.environ["RUN_URL"]
    digest = os.environ.get("DIGEST", "")
    ev = json.loads(Path(evidence_path).read_text())

    # 1. Register the ledger of VERIFIED attestation types for this digest
    verified_types = [s["tool"] for s in ev["scans"] if s["verified"]]
    if ev["provenance"]["verified"] and "sast" not in verified_types:
        pass  # provenance registered separately below for clarity
    print(f"[sde] marking {len(verified_types)} verified scan attestations: {verified_types}", flush=True)
    if not verified_types:
        print("[sde] no verified scan attestations -> countermeasures stay/become Incomplete")

    exit_code = 0
    try:
        if verified_types:
            r = api("POST", "/sde/attestations", {"digest": digest, "types": verified_types},
                    os.environ["SDE_TOKEN"])
            print(f"[sde] registered {r}", flush=True)

        # 2. Per-check status
        status_map = {"sast": "T-SAST", "sca": "T-SCA", "secrets": "T-SECRETS"}
        for s in ev["scans"]:
            cm_id = status_map[s["tool"]]
            clean = (s["verified"] and s["critical"] == 0 and s["high"] == 0
                     and s["secrets"] == 0)
            status = "Complete" if clean else "Incomplete"
            note = (f"{decision}: {s['tool']} critical={s['critical']} high={s['high']} "
                    f"secrets={s['secrets']} | run={run_url} | digest={digest}")
            api("POST", f"/sde/countermeasure/{cm_id}",
                {"status": status, "note": note, "digest": digest, "run_url": run_url,
                 "attestation_verified": s["verified"]},
                os.environ["SDE_TOKEN"])
            print(f"[sde] {cm_id} -> {status}", flush=True)

        # 3. Reconcile: reverts anything lacking a matching verified attestation
        rec = api("POST", "/sde/reconcile", {"note": f"digest={digest}"}, os.environ["SDE_TOKEN"])
        print(f"[sde] reconcile: {json.dumps(rec)}", flush=True)
        if rec["reverted"]:
            print(f"::warning::mock SDE reverted {rec['reverted']} — "
                  "some countermeasure claimed Complete without a verified attestation")

        for a in api("GET", "/sde/alerts", token=os.environ["SDE_TOKEN"]):
            print(f"[sde ALERT] {a['msg']}", flush=True)

        # 4. Digest note on CR
        cr_id = os.environ.get("CR_ID", "")
        if cr_id:
            api("POST", f"/change/{cr_id}/resolve",
                {"approved": decision == "auto_approve",
                 "note": f"digest={digest} | {run_url}"},
                os.environ["CR_TOKEN"])
    except Exception as e:
        print(f"::error::mock SDE update failed: {e}", file=sys.stderr)
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
