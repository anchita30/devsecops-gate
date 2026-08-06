import json
import sys

CVE_REPORT = "trivy-cve-report.json"
LICENSE_REPORT = "license-report.json"
BLOCKED_LICENSE_PREFIXES = ["GPL", "AGPL"]

failures = []

# Rule 1: block CRITICAL CVEs with no fix available
with open(CVE_REPORT) as f:
    cve_data = json.load(f)

for result in cve_data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        severity = vuln.get("Severity", "")
        fixed_version = vuln.get("FixedVersion", "")
        if severity == "CRITICAL" and not fixed_version:
            failures.append(
                f"CRITICAL CVE with no fix: {vuln.get('VulnerabilityID')} "
                f"in {vuln.get('PkgName')}"
            )

# Rule 2: block GPL-family licenses
with open(LICENSE_REPORT) as f:
    license_data = json.load(f)

for result in license_data.get("Results", []):
    for lic in result.get("Licenses", []):
        name = lic.get("Name", "")
        # Match only strict GPL/AGPL, not LGPL (LGPL starts with "L", not "GPL"/"AGPL")
        if any(name.upper().startswith(prefix) for prefix in BLOCKED_LICENSE_PREFIXES):
            failures.append(
                f"Blocked license '{name}' found in {lic.get('PkgName', 'unknown package')}"
            )

# Decision
if failures:
    print("POLICY GATE: FAILED")
    for reason in failures:
        print(f"  - {reason}")
    sys.exit(1)
else:
    print("POLICY GATE: PASSED — no blocking issues found")
    sys.exit(0)