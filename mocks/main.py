"""Mock ServiceNow (change requests) and SD Elements (countermeasures).

FastAPI app. Runs locally; exposed to GitHub Actions via a cloudflared quick tunnel.

Auth model (Bearer tokens, configurable via env for production-ish values):
  - MOCK_SDE_TOKEN_CI   -> "ci" role: may change countermeasures.
  - MOCK_SDE_TOKEN_DEV  -> "developer" role: gets 403. Demonstrates that only CI
                           automation owns countermeasure state.
  - MOCK_CR_TOKEN       -> may file/read/resolve change requests.

Reconciliation: C.I. callers must first register verified attestations for a
digest via POST /sde/attestations (only done in the release workflow AFTER cosign
has verified the attestations). Any countermeasure whose latest change lacks a
matching attestation for its digest is reverted and an alert is logged.
"""
import os
import time
import uuid
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

CR_TOKEN = os.environ.get("MOCK_CR_TOKEN", "cr-token")
SDE_CI_TOKEN = os.environ.get("MOCK_SDE_TOKEN_CI", "ci-token")
SDE_DEV_TOKEN = os.environ.get("MOCK_SDE_TOKEN_DEV", "dev-token")

app = FastAPI(title="supply-chain-lab mock ServiceNow + SD Elements")

CM_IDS = ("T-SAST", "T-SCA", "T-SECRETS")
CM_TO_TYPE = {"T-SAST": "sast", "T-SCA": "sca", "T-SECRETS": "secrets"}


def _fresh_state() -> dict:
    return {
        # change request id -> record
        "changes": {},
        # countermeasure id -> {"status", "note", "digest", "run_url", "prev_status"}
        "countermeasures": {cid: {"status": "Incomplete", "note": "initial",
                                  "digest": None, "run_url": None, "prev_status": None}
                            for cid in CM_IDS},
        "alerts": [],
        "audit": [],          # every countermeasure change attempt
        "attestations": [],   # {"digest", "types", "ts"} posted only after verification
    }


state = _fresh_state()


def _sde_role(auth: Optional[str]) -> Optional[str]:
    token = (auth or "").removeprefix("Bearer ").strip()
    if token == SDE_CI_TOKEN:
        return "ci"
    if token == SDE_DEV_TOKEN:
        return "developer"
    return None


def _cr_ok(auth: Optional[str]) -> bool:
    return (auth or "").removeprefix("Bearer ").strip() == CR_TOKEN


# ----------------------------- ServiceNow mock -----------------------------

class ChangeRequest(BaseModel):
    decision: str          # auto_approve | manual | reject
    digest: str
    run_url: str
    evidence: dict         # the evidence bundle built from verified attestations


class ChangeResolve(BaseModel):
    approved: bool
    note: str = ""


@app.post("/change", status_code=201)
def create_change(cr: ChangeRequest, authorization: Optional[str] = Header(None)):
    if not _cr_ok(authorization):
        raise HTTPException(401, "invalid CR token")
    cid = "CR" + uuid.uuid4().hex[:10].upper()
    rec = cr.model_dump()
    rec.update(id=cid, approved=(cr.decision == "auto_approve"),
               manual_gap=(cr.decision == "manual"), ts=time.time())
    state["changes"][cid] = rec
    return rec


@app.get("/change/{cid}")
def get_change(cid: str, authorization: Optional[str] = Header(None)):
    if not _cr_ok(authorization):
        raise HTTPException(401, "invalid CR token")
    if cid not in state["changes"]:
        raise HTTPException(404, "no such CR")
    return state["changes"][cid]


@app.post("/change/{cid}/resolve")
def resolve_change(cid: str, body: ChangeResolve, authorization: Optional[str] = Header(None)):
    if not _cr_ok(authorization):
        raise HTTPException(401, "invalid CR token")
    if cid not in state["changes"]:
        raise HTTPException(404, "no such CR")
    state["changes"][cid]["approved"] = body.approved
    state["changes"][cid]["manual_gap"] = False
    state["changes"][cid]["note"] = body.note
    return state["changes"][cid]


# ----------------------------- SD Elements mock -----------------------------

class CountermeasureUpdate(BaseModel):
    status: str                 # Complete | Incomplete
    note: str = ""
    digest: Optional[str] = None
    run_url: Optional[str] = None
    attestation_verified: bool = False


class AttestationLedger(BaseModel):
    digest: str
    types: list[str]            # e.g. ["sast","sca","secrets"] verified for digest


class TokenOnly(BaseModel):
    note: str = ""


def _actor(auth: Optional[str]) -> str:
    r = _sde_role(auth)
    if r is None:
        raise HTTPException(401, "invalid SDE token")
    return r


@app.post("/sde/countermeasure/{cid}")
def set_countermeasure(cid: str, body: CountermeasureUpdate,
                       authorization: Optional[str] = Header(None)):
    actor = _actor(authorization)
    if actor == "developer":
        raise HTTPException(403, "countermeasure state is CI-owned; developers may not change it")
    if cid not in CM_IDS:
        raise HTTPException(404, "unknown countermeasure")
    if body.status not in ("Complete", "Incomplete"):
        raise HTTPException(400, "status must be Complete or Incomplete")
    cm = state["countermeasures"][cid]
    change = {"id": cid, "actor": actor, "from": cm["status"], "to": body.status,
              "digest": body.digest, "ts": time.time(),
              "attestation_verified": bool(body.attestation_verified)}
    if body.status != cm["status"]:
        cm["prev_status"] = cm["status"]
    cm.update(status=body.status, note=body.note, digest=body.digest, run_url=body.run_url)
    state["audit"].append(change)
    return cm


@app.post("/sde/attestations")
def register_attestations(body: AttestationLedger, authorization: Optional[str] = Header(None)):
    _actor(authorization)  # CI token required to register verified evidence
    state["attestations"].append({"digest": body.digest, "types": sorted(body.types),
                                  "ts": time.time()})
    return {"registered": len(body.types)}


def _has_attestation(digest: str, ctype: str) -> bool:
    return any(a["digest"] == digest and ctype in a["types"]
               for a in state["attestations"])


@app.post("/sde/reconcile")
def reconcile(authorization: Optional[str] = Header(None), t: TokenOnly = None):
    _actor(authorization)  # CI token only
    reverted, alerts = [], []
    for cid in CM_IDS:
        cm = state["countermeasures"][cid]
        ctype = CM_TO_TYPE[cid]
        if cm["status"] == "Complete" and not _has_attestation(cm["digest"] or "", ctype):
            reverted.append(cid)
            alerts.append({
                "ts": time.time(), "countermeasure": cid,
                "msg": (f"{cid} set to Complete without a matching verified attestation "
                        f"(digest={cm['digest']}); reverted. This would have been an "
                        "untriaged countermeasure."),
            })
            cm["status"] = cm["prev_status"] if cm["prev_status"] else "Incomplete"
            cm["prev_status"] = None
    state["alerts"].extend(alerts)
    return {"reverted": reverted, "alerts": alerts}


@app.get("/sde/countermeasures")
def list_countermeasures():
    return state["countermeasures"]


@app.get("/sde/alerts")
def list_alerts():
    return state["alerts"]


@app.get("/health")
def health():
    return {"ok": True}
