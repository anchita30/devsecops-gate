# DevSecOps Supply-Chain Gate

A CI/CD security checkpoint that inspects every build before it can deploy — generating a full inventory of dependencies, scanning for known vulnerabilities and license issues, enforcing configurable policy rules, and cryptographically signing only the builds that pass.

## The problem this solves

Modern applications are built almost entirely out of third-party code, a small Flask app can easily pull in dozens of transitive dependencies nobody explicitly chose. Without visibility into what's actually inside a build, teams have no way to know if they're shipping a known vulnerability, an incompatible open-source license, or a tampered artifact. This pipeline makes that visibility automatic and enforced, rather than optional and manual.

## Architecture
Push to main
│
▼
Build Docker image
│
▼
Generate SBOM (Syft) ──────────► full dependency inventory
│
▼
Scan SBOM for CVEs (Trivy) ────► known vulnerabilities, by severity
│
▼
Scan for license issues (Trivy, app-level only) ──► license names per package
│
▼
Policy Gate (policy_gate.py + policy/policy.yaml)
│
├── FAIL ──► pipeline stops here, nothing pushed or signed
│
▼ PASS
Push image to GHCR
│
▼
Sign image (cosign, keyless via Sigstore) ──► signature + certificate recorded in Rekor
│
▼
Verify signature (cosign verify) ──► confirms signer identity matches this exact repo/workflow
│
▼
Deploy (simulated)

## Tech stack

| Tool | Role |
|---|---|
| GitHub Actions | CI/CD orchestration |
| Docker | Application packaging |
| Syft | SBOM generation (CycloneDX format) |
| Trivy | CVE scanning and license scanning |
| Python | Policy gate enforcement logic |
| Sigstore / cosign | Keyless artifact signing and verification |
| GitHub Container Registry (GHCR) | Image storage |

## Running it

Every check runs automatically on push or pull request to `main`. Artifacts (SBOM, CVE report, license report) are downloadable from each workflow run under the Actions tab. Signed images are published to `ghcr.io/<owner>/devsecops-gate-demo`.

To verify a build's signature independently: