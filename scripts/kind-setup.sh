#!/usr/bin/env bash
# Local kind + Kyverno setup for the supply-chain lab deploy gate.
# Run AFTER the first successful CI build (image + attestations must exist in GHCR,
# and the package must be public: https://github.com/users/rajumandala/packages).
set -euo pipefail

KYVERNO_VERSION=${KYVERNO_VERSION:-v1.15.2}
IMAGE_NAME=${IMAGE_NAME:-ghcr.io/rajumandala/supply-chain-lab}

# 1. cluster
kind delete cluster --name scs-lab >/dev/null 2>&1 || true
kind create cluster --name scs-lab

# 2. Kyverno
kubectl create -f "https://raw.githubusercontent.com/kyverno/kyverno/${KYVERNO_VERSION}/config/install.yaml"
kubectl -n kyverno wait --for=condition=available deploy --all -n kyverno --timeout=300s

# 3. policy
kubectl apply -f kyverno/clusterpolicy-verify-supply-chain.yaml

echo "kind cluster 'scs-lab' + Kyverno ready."
