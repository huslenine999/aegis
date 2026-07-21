# NIST SSDF 1.1 implementation matrix

| Practice | Status | Aegis evidence or gap |
| --- | --- | --- |
| PO.1 Security requirements | Partial | Threat model, hardening baseline and release checklist; formal owner approval pending |
| PO.2 Roles and responsibilities | Partial | CODEOWNERS and incident roles; named production personnel pending |
| PO.3 Toolchain implementation | Implemented | Pinned CI actions, scanner workflow, dependency locking and release benchmark |
| PO.4 Security criteria for software | Partial | Policy gate and ASVS applicability map; independent acceptance pending |
| PO.5 Secure development environments | Partial | Protected workflows and isolated scanning design; organizational endpoint controls external |
| PS.1 Protect code | Partial | Git controls and review ownership; branch protection must be enabled in repository settings |
| PS.2 Provide release integrity | Implemented | Checksums, signed manifests, GitHub/Sigstore provenance and container SBOM/provenance |
| PS.3 Archive and protect releases | Partial | GitHub artifacts and image registry; immutable retention policy external |
| PW.1 Design security | Implemented | Threat model, trust boundaries, fail-closed production profile |
| PW.2 Review design | Partial | Internal evidence exists; independent architecture review pending |
| PW.4 Reuse secure components | Partial | Locked dependencies and update automation; approved-component policy pending |
| PW.5 Create source securely | Implemented | Security linting, tests, review gates and suppression evidence |
| PW.6 Configure builds securely | Implemented | Hosted release workflow, pinned actions, SBOM and provenance |
| PW.7 Review/analyze code | Implemented | Ruff, Semgrep, dependency, secret and malware-oriented checks |
| PW.8 Test executable code | Partial | Browser, policy, sandbox and benchmark tests; broad DAST and pentest pending |
| PW.9 Configure software securely | Implemented | Production validation, secure defaults and deployment guidance |
| RV.1 Identify vulnerabilities | Partial | VDP and automated scanners; external researcher intake operational staffing pending |
| RV.2 Assess and remediate | Partial | Severity and incident workflows; measured remediation SLA history pending |
| RV.3 Analyze root causes | Partial | Post-incident process documented; exercised evidence pending |

This matrix is a self-assessment, not certification. Review it quarterly and
attach immutable evidence for every status change.
