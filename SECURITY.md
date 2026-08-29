# Security Policy

## Project status

UBDA is a **prototype / educational project** exploring a capability-based
data access architecture. It is not audited, not hardened, and not intended
to protect real secrets in production. See the warning at the top of the
[README](README.md) for details — in particular, `MockHardwareAuthorizer`
uses an in-process Ed25519 keypair and a hard-coded demo secret in place of a
real HSM/TEE.

That said, if you find a genuine flaw in the *design* (e.g. a way to bypass
trust-state enforcement, forge a capability, or defeat replay protection
within the model as specified), that's a meaningful and welcome finding.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security findings.

Instead, use GitHub's private vulnerability reporting for this repository
(Security tab → "Report a vulnerability"), or reach out directly to the
maintainer. Please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a minimal example
- Whether it affects the architectural design itself vs. this specific
  prototype implementation

## Response expectations

This is a small, self-taught, part-time project — please expect a best-effort
response rather than a guaranteed SLA. Reports will be acknowledged as soon
as reasonably possible.
