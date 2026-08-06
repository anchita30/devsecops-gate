import json
import sys
from datetime import date
import yaml

POLICY_FILE = "policy/policy.yaml"
CVE_REPORT = "trivy-cve-report.json"
LICENSE_REPORT = "license-report.json"

with open(POLICY_FILE) as f:
    policy = yaml.safe_load(f)

blocked_severities = policy["cve_policy"]["blocked_severities"]
exemptions = {e["id"]: e for e in policy["cve_policy"].get("exemptions", [])}
blocked_license_prefixes = policy["license_policy"]["blocked_prefixes"]

failures = []


def is_exemption_active(cve_id):
    """Return True if this CVE has a valid, not-yet-expired exemption."""
    exemption = exemptions.get(cve_id)
    if not exemption:
        return False
    expiry_date = date.fromisoformat(exemption["expires"])
    return date.today() <= expiry_date


with open(CVE_REPORT) as f:
    cve_data = json.load(f)

for result in cve_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        severity = vuln.get("Severity", "")
        fixed_version = vuln.get("FixedVersion", "")
        vuln_id = vuln.get("VulnerabilityID", "")
        if severity in blocked_severities and not fixed_version:
            if is_exemption_active(vuln_id):
                continue  # exempted and still valid, skip it
            failures.append(f"{severity} CVE with no fix: {vuln_id} in {vuln.get('PkgName')}")

with open(LICENSE_REPORT) as f:
    license_data = json.load(f)

for result in license_data.get("Results", []):
    for lic in result.get("Licenses", []):
        name = lic.get("Name", "")
        if any(name.upper().startswith(p.upper()) for p in blocked_license_prefixes):
            failures.append(f"Blocked license '{name}' found in {lic.get('PkgName', 'unknown package')}")

if failures:
    print("POLICY GATE: FAILED")
    for reason in failures:
        print(f"  - {reason}")
    sys.exit(1)
else:
    print("POLICY GATE: PASSED — no blocking issues found")
    sys.exit(0)