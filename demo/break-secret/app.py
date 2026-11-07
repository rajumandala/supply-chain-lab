import os

# FIXTURE for the "break it" demo: a hardcoded credential. This is NOT a real
# secret, and it is deliberately allowlisted so the repo-wide scan passes; the
# break-it demo adds new fake secrets WITHOUT the marker and they fail the gate.
GITHUB_TOKEN = "ghp_S3mPl3FaK3T0k3n1234567890aabbccdd"  # gitleaks:allow
API_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow - also a known-bad example pattern
