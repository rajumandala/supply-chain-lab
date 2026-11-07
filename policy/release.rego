package release

import rego.v1

# Gate for the supply-chain-lab release pipeline.
#
# input is the evidence bundle, built ONLY from attestations that cosign has
# cryptographically verified against the repo's workflow identity:
#   input.provenance.verified                  bool
#   input.provenance.builder_id               string
#   input.provenance.source                   string (github.com/OWNER/REPO...)
#   input.scans        : array of {tool, verified, critical, high, secrets}
#   input.changed_paths: array of strings (from the release in question)

repo := "github.com/rajumandala/supply-chain-lab"

builder_id := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"

required_scan_tools := {"sast", "sca", "secrets"}

critical_count := sum([s.critical | some s in input.scans])

high_count := sum([s.high | some s in input.scans])

secrets_count := sum([s.secrets | some s in input.scans])

provenance_ok if {
	input.provenance.verified
	startswith(input.provenance.builder_id, builder_id)
	startswith(input.provenance.source, repo)
}

scan_ok(tool) if {
	some s in input.scans
	s.tool == tool
	s.verified
}

all_scans_present if {
	every t in required_scan_tools {
		scan_ok(t)
	}
}

sensitive_path if {
	compound := {"auth/", "payments/", "migrations/"}
	some p in input.changed_paths
	some d in compound
	startswith(p, d)
}

# ----------------------------- decision tree -----------------------------
# reject : missing/invalid provenance, wrong builder or repo, any critical
#          finding, missing scan attestation, any secrets found
# manual : any high finding, or sensitive path changed
# auto_approve : otherwise

decision := "reject" if not provenance_ok

decision := "reject" if {
	some s in input.scans
	not s.verified
}

decision := "reject" if not all_scans_present

decision := "reject" if critical_count > 0

decision := "reject" if secrets_count > 0

decision := "manual" if {
	critical_count == 0
	secrets_count == 0
	provenance_ok
	all_scans_present
	high_count > 0
}

decision := "manual" if {
	critical_count == 0
	secrets_count == 0
	provenance_ok
	all_scans_present
	high_count == 0
	sensitive_path
}

decision := "auto_approve" if {
	critical_count == 0
	secrets_count == 0
	provenance_ok
	all_scans_present
	high_count == 0
	not sensitive_path
}

default decision := "reject"

# ----------------------------- reasons -----------------------------

reasons contains "provenance missing or does not match expected builder/repo" if not provenance_ok

reasons contains msg if {
	some s in input.scans
	not s.verified
	msg := concat("", ["scan attestation not verified: ", s.tool])
}

reasons contains msg if {
	some t in required_scan_tools
	not scan_ok(t)
	msg := concat("", ["missing scan attestation: ", t])
}

reasons contains "critical severity findings present" if critical_count > 0

reasons contains "high severity findings present: manual review required" if {
	high_count > 0
	critical_count == 0
	secrets_count == 0
	provenance_ok
	all_scans_present
}

reasons contains msg if {
	critical_count == 0
	secrets_count == 0
	provenance_ok
	all_scans_present
	high_count == 0
	sensitive_path
	msg := "sensitive path changed (auth/, payments/, or migrations/): manual review required"
}

reasons contains "secrets detected" if {
	secrets_count > 0
	provenance_ok
	all_scans_present
}

reasons contains "no blocking findings: auto approved" if {
	critical_count == 0
	secrets_count == 0
	provenance_ok
	all_scans_present
	high_count == 0
	not sensitive_path
}
