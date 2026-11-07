from app import app


def test_hello():
    client = app.test_client()
    resp = client.get("/hello")
    assert resp.status_code == 200
    assert resp.json["message"] == "hello"
    assert resp.json["service"] == "supply-chain-lab"
