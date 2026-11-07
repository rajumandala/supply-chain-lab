package release_test

import rego.v1

import data.release

good_input := {
	"provenance": {
		"verified": true,
		"builder_id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/heads/main",
		"source": "github.com/rajumandala/supply-chain-lab/.github/workflows/build.yml@refs/heads/main",
	},
	"scans": [
		{"tool": "sast", "verified": true, "critical": 0, "high": 0, "secrets": 0},
		{"tool": "sca", "verified": true, "critical": 0, "high": 0, "secrets": 0},
		{"tool": "secrets", "verified": true, "critical": 0, "high": 0, "secrets": 0},
	],
	"changed_paths": ["app.py"],
}

# ------------------------------- happy path -------------------------------

test_auto_approve_clean_change if {
	r := release.decision with input as good_input
	r == "auto_approve"
}

test_auto_approve_missing_changed_paths if {
	test_in := object.union(good_input, {"changed_paths": []})
	release.decision with input as test_in == "auto_approve"
}

# ------------------------------- reject: provenance -------------------------------

test_reject_missing_provenance if {
	test_in := object.union(good_input, {"provenance": {"verified": false,
		"builder_id": good_input.provenance.builder_id, "source": good_input.provenance.source}})
	release.decision with input as test_in == "reject"
}

test_reject_builder_mismatch if {
	test_in := object.union(good_input, {"provenance": object.union(good_input.provenance, {
		"builder_id": "https://github.com/evil/generator.rip/.github/workflows/generator_container_slsa3.yml@refs/heads/main",
	})})
	release.decision with input as test_in == "reject"
}

test_reject_repo_mismatch if {
	test_in := object.union(good_input, {"provenance": object.union(good_input.provenance, {
		"source": "github.com/attacker/supply-chain-lab/.github/workflows/build.yml@refs/heads/main",
	})})
	release.decision with input as test_in == "reject"
}

# ------------------------------- reject: scans -------------------------------

test_reject_missing_scan_attestation if {
	test_in := object.union(good_input, {"scans": [s | some i, s in good_input.scans; i != 0]})
	release.decision with input as test_in == "reject"
}

test_reject_unverified_scan if {
	test_in := object.union(good_input, {"scans": [
		object.union(s, {"verified": false}) | some i, s in good_input.scans
	]})
	release.decision with input as test_in == "reject"
}

test_reject_critical_finding if {
	test_in := object.union(good_input, {"scans": [
		object.union(s, {"critical": 1}) | some i, s in good_input.scans
	]})
	release.decision with input as test_in == "reject"
}

test_reject_secret_found if {
	test_in := object.union(good_input, {"scans": [
		object.union(s, {"secrets": 1}) | some i, s in good_input.scans
	]})
	release.decision with input as test_in == "reject"
}

# ------------------------------- manual -------------------------------

test_manual_high_finding if {
	test_in := object.union(good_input, {"scans": [
		object.union(s, {"high": 1}) | some i, s in good_input.scans
	]})
	release.decision with input as test_in == "manual"
}

test_manual_sensitive_path_auth if {
	test_in := object.union(good_input, {"changed_paths": ["app.py", "auth/login.py"]})
	release.decision with input as test_in == "manual"
}

test_manual_sensitive_path_payments if {
	test_in := object.union(good_input, {"changed_paths": ["payments/charge.py"]})
	release.decision with input as test_in == "manual"
}

test_manual_sensitive_path_migrations if {
	test_in := object.union(good_input, {"changed_paths": ["migrations/002_add_col.py"]})
	release.decision with input as test_in == "manual"
}

test_clean_but_high_missing_elsewhere_not_manual if {
	# high + critical -> reject takes precedence over manual
	test_in := object.union(good_input, {"scans": [
		object.union(s, {"high": 1, "critical": 1}) | some i, s in good_input.scans
	]})
	release.decision with input as test_in == "reject"
}
