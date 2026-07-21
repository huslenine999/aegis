# OWASP ASVS 5.0 applicability and evidence map

This is the maintained Aegis applicability register for ASVS 5.0.0. It is not an
independent verification. Requirement identifiers include the standard version
to avoid ambiguity. The complete official ASVS remains the source of truth.

| ASVS area | Status | Evidence and next verification |
| --- | --- | --- |
| v5.0.0-V1 Encoding and Sanitization | Partial | Parameterized SQL, safe template rendering and command arrays; complete endpoint-by-endpoint review pending |
| v5.0.0-V2 Validation and Business Logic | Partial | Typed validation, limits, tenant consistency triggers; concurrency abuse review pending |
| v5.0.0-V3 Web Frontend Security | Partial | CSP nonces, HSTS production proxy, nosniff, safe text rendering and browser tests |
| v5.0.0-V4 API and Web Service | Partial | Authentication, scoped tokens, body/rate limits and webhook integrity; full schema inventory pending |
| v5.0.0-V5 File Handling | Partial | Symlink/special-file rejection, bounded trees, isolated artifact paths and integrity checks |
| v5.0.0-V6 Authentication | Partial | Password hashing, lockout, replay-safe TOTP and recovery codes; OIDC/WebAuthn pending |
| v5.0.0-V7 Session Management | Partial | Opaque server sessions, Secure/HttpOnly/SameSite cookies, CSRF, revocation and recent auth |
| v5.0.0-V8 Authorization | Partial | RBAC, membership, tenant scope and DB guards; PostgreSQL RLS and independent test pending |
| v5.0.0-V9 Self-contained Tokens | Not applicable | Browser identity does not use self-contained bearer JWTs; GitHub App JWT is outbound service authentication |
| v5.0.0-V10 OAuth and OIDC | Partial | OAuth state, PKCE and encrypted token storage; enterprise OIDC and formal provider review pending |
| v5.0.0-V11 Cryptography | Partial | Fernet, HMAC, Ed25519 and secure randomness; KMS lifecycle and crypto inventory review pending |
| v5.0.0-V12 Secure Communication | Partial | TLS proxy and outbound certificate validation; deployed TLS scan evidence pending |
| v5.0.0-V13 Configuration | Partial | Production startup rejects insecure modes, wildcards, SQLite and missing controls |
| v5.0.0-V14 Data Protection | Partial | Scoped access, encrypted credentials and retention; immutable object storage and verified deletion pending |
| v5.0.0-V15 Secure Coding and Architecture | Partial | Threat model, sandbox and fail-closed scanner state; independent architecture review pending |
| v5.0.0-V16 Security Logging and Error Handling | Partial | HMAC audit chain, append-only triggers and structured logs; durable external SIEM pending |
| v5.0.0-V17 WebRTC | Not applicable | Aegis does not implement WebRTC |

Before claiming an ASVS level, import the official stable CSV, record every
individual requirement as Applicable, Not Applicable, or Not Reviewed, attach
test evidence, and obtain review by an assessor independent of implementation.
