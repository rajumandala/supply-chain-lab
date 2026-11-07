#!/usr/bin/env bash
# Deploy demo: good digest (CI-built, attested) vs unsigned locally-built image.
# usage: demo-kind.sh <good-image-digest>   e.g. sha256:abc...
set -euo pipefail

DIGEST=${1:?usage: demo-kind.sh sha256:<hex>}
GOOD_IMAGE="ghcr.io/rajumandala/supply-chain-lab@${DIGEST}"

echo "== 1. good digest: should deploy"
kubectl run good-after --image="$GOOD_IMAGE" --restart=Never 2>&1 | sed 's/^/  /'

echo "== 2. locally-built unsigned image: should be rejected"
cat > /tmp/unsigned-Dockerfile <<'EOF'
FROM python:3.13-alpine
WORKDIR /app
COPY app.py .
CMD ["python", "-c", "import time; time.sleep(3600)"]
EOF
docker build -f /tmp/unsigned-Dockerfile -q -t ghcr.io/rajumandala/supply-chain-lab:unsigned-local . >/dev/null
kind load docker-image ghcr.io/rajumandala/supply-chain-lab:unsigned-local --name scs-lab >/dev/null
echo "  image loaded into kind (no signatures/attestations)"
set +e
kubectl run bad-sneaky --image=ghcr.io/rajumandala/supply-chain-lab:unsigned-local --restart=Never 2>&1 | sed 's/^/  /'
echo "exit: $?"
set -e
echo "expected: the kubectl apply above is blocked by Kyverno with an attestation error."
