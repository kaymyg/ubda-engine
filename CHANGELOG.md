# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0-alpha] - 2026-08-28

### Added
- Initial public release of the UBDA trust-state engine: `TrustState` /
  `DataClassification` model, `SystemStateMachine`, `BehavioralTrustEngine`,
  `MockHardwareAuthorizer` (`KeyAuthority`), `KeyBroker`, and `ReplayStore`.
- End-to-end CLI walkthrough (`cargo run`) exercising the full T0→T4 trust
  lifecycle, including D0–D3 capability issuance, replay defense, signature
  tamper detection, and compromise lockout/recovery.
- 17-test unit suite covering state transitions, capability issuance,
  key-broker verification (signature, expiry, replay, session binding,
  operation matching), and derived-key determinism.
- Architecture documentation (`docs/ARCHITECTURE.md`) with trust-state and
  component-isolation diagrams.
- Live Gradio demo Space and a Hugging Face dataset backup of the source.
- CI (fmt, clippy, build, test), issue/PR templates, security policy,
  contributing guide, and Dependabot config.

### Notes
- `MockHardwareAuthorizer` is a software stand-in for a real hardware/TEE key
  authority — see the README's prototype-status warning.
