FROM python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Upgrade transitive base packages with known HIGH CVEs (trivy SCA):
#   CVE-2026-114613 / GHSA-6v7p-g79w-8964 (msgpack), CVE-2025-47273
#   (setuptools), CVE-2026-97687 / CVE-2026-97689 (urllib3)
RUN pip install --no-cache-dir --upgrade \
      "msgpack>=1.2.3" "setuptools>=78.1.1" "urllib3>=2.8.0"
COPY app.py .
USER 1000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8000/hello || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
