import pytest
from fastapi.testclient import TestClient

from main import CM_IDS, app, state


@pytest.fixture(autouse=True)
def fresh_state():
    state.update(**{
        "changes": {},
        "countermeasures": {cid: {"status": "Incomplete", "note": "initial",
                                  "digest": None, "run_url": None,
                                  "prev_status": None} for cid in CM_IDS},
        "alerts": [], "audit": [], "attestations": [],
    })
    yield


CI = {"Authorization": "Bearer ci-token"}
DEV = {"Authorization": "Bearer dev-token"}
CR = {"Authorization": "Bearer cr-token"}
client = TestClient(app)


def test_cr_roundtrip():
    body = {"decision": "auto_approve", "digest": "sha256:abc",
            "run_url": "https://github.com/x/actions/runs/1", "evidence": {"ok": True}}
    r = client.post("/change", json=body, headers=CR)
    assert r.status_code == 201
    cid = r.json()["id"]
    g = client.get(f"/change/{cid}", headers=CR)
    assert g.status_code == 200
    assert g.json()["decision"] == "auto_approve"
    assert g.json()["approved"] is True


def test_developer_token_blocked():
    """The 'break it' demo: a developer marking T-SAST Complete must be blocked."""
    r = client.post("/sde/countermeasure/T-SAST",
                    json={"status": "Complete", "note": "looks done to me"},
                    headers=DEV)
    assert r.status_code == 403
    listing = client.get("/sde/countermeasures").json()
    assert listing["T-SAST"]["status"] == "Incomplete"


def test_reconcile_reverts_unattested_change():
    """CI marks T-SAST Complete but no verified attestation exists -> reconciliation
    reverts it and logs an alert."""
    r = client.post("/sde/countermeasure/T-SAST",
                    json={"status": "Complete", "digest": "sha256:deadbeef",
                          "note": "build run"}, headers=CI)
    assert r.status_code == 200
    assert r.json()["status"] == "Complete"

    rec = client.post("/sde/reconcile", headers=CI).json()
    assert "T-SAST" in rec["reverted"]
    assert any("T-SAST" in a["countermeasure"] for a in client.get("/sde/alerts").json())
    assert client.get("/sde/countermeasures").json()["T-SAST"]["status"] == "Incomplete"


def test_reconcile_keeps_attested_change():
    client.post("/sde/attestations",
                json={"digest": "sha256:cafe", "types": ["sca"]}, headers=CI)
    r = client.post("/sde/countermeasure/T-SCA",
                    json={"status": "Complete", "digest": "sha256:cafe",
                          "note": "trivy clean"}, headers=CI)
    assert r.json()["status"] == "Complete"
    rec = client.post("/sde/reconcile", headers=CI).json()
    assert rec["reverted"] == []
    assert client.get("/sde/countermeasures").json()["T-SCA"]["status"] == "Complete"
