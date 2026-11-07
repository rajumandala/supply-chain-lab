"""Supply chain security lab: minimal Flask API."""
from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/hello")
def hello():
    return jsonify(message="hello", service="supply-chain-lab", version="1.0.0")
