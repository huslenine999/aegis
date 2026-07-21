# Buyer security package index

Provide this index under NDA during technical due diligence. Mark every answer
with an evidence link, owner, review date, and one of Implemented, Partial,
Planned, Not Applicable, or External Customer Control.

| Buyer topic | Current evidence |
| --- | --- |
| Architecture and trust boundaries | `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` |
| Product security overview | `docs/SECURITY_WHITEPAPER.md` |
| Application controls | `docs/HARDENING.md`, tests and release benchmark |
| Secure development lifecycle | `docs/SSDF_MATRIX.md`, CI workflows, CODEOWNERS |
| Identity and access | MFA, recent-auth, scoped-token and tenant tests |
| Encryption and keys | `docs/PRODUCTION.md`, signed evidence implementation |
| Vulnerability management | `SECURITY.md`, `docs/INCIDENT_RESPONSE.md` |
| Business continuity | backup/restore commands and `docs/OPERATIONS.md` |
| Independent assurance | `docs/PENTEST_SCOPE.md`; report remains outstanding |
| Availability commitment | `docs/SLA_TEMPLATE.md`; becomes contractual only when signed |
| Data handling | `docs/DATA_HANDLING.md`; legal review remains outstanding |

Never answer “compliant” solely because a technical control exists. SOC 2,
ISO 27001, PCI DSS, financial-sector requirements, and privacy obligations
require scoped organizational evidence and, where applicable, an authorized
auditor or legal counsel.
