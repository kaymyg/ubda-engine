---
license: mit
---

# UBDA — Unified Behavioral Data Access (V1.2-alpha)

UBDA is a prototype **capability-based data access architecture** written in Rust. It
models a system where a software behavioral-trust engine can *influence* trust
levels, but only a separate hardware/TEE-style authority can ever mint the
signed, short-lived capabilities that unlock encryption keys. The goal is to
explore the design pattern — not to ship a production security product.

> ⚠️ **Prototype / educational status.** This is a self-teaching / architecture
> exploration project. `MockHardwareAuthorizer` uses an in-memory Ed25519
> keypair and a hard-coded demo secret in place of a real HSM/TEE, and Ed25519
> is used as a placeholder for a future post-quantum signature scheme. Do not
> use this as-is to protect real secrets.

## Concept

* **Trust states (`T-1`…`T4`)** describe how strongly the system currently
  trusts the requester, moving from a cold, unauthenticated boot through
  device authentication, behavioral continuity, step-up (biometric/PIN), and
  finally hardware-backed critical elevation.
* **Data classifications (`D0`…`D3`)** describe how sensitive a resource is,
  from public system files up to root/master key material.
* Every classification has a **minimum required trust state**. The
  `KeyAuthority` first verifies the Behavioral Trust Engine's signed, fresh
  policy assertion, then refuses to issue a capability when its asserted trust
  state does not meet that classification's minimum.
* A **Data Access Capability (DAC)** is a signed, time-boxed, single-use,
  resource-scoped grant. The authority generates an unpredictable nonce and
  validates a positive, non-overflowing TTL. The `KeyBroker` independently
  re-verifies the DAC's signature, expiry, trust-state requirement, operation,
  and session binding, then rejects replay before asking the authority to
  derive an ephemeral session key (HKDF-SHA256) bound to the complete DAC scope.
* A hard anomaly signal (or an intrusion interrupt) forces the whole system
  into a `Compromised` (`T-1`) state where all key material is invalidated
  until an explicit hardware recovery reset.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full state-transition
diagram, component-isolation diagram, and the trust/classification matrix.

## Project layout

```
src/
  types.rs               Core enums/structs: TrustState, DataClassification,
                          DataAccessCapability, telemetry & assertion types
  state_machine.rs        SystemStateMachine — enforces valid trust transitions
  bte_interface.rs         BehavioralTrustEngine — turns telemetry into a PolicyAssertion
  hardware_authorizer.rs   KeyAuthority trait + MockHardwareAuthorizer (Ed25519 + HKDF)
  key_broker.rs            KeyBroker — verifies & consumes DACs, derives session keys
  replay_store.rs          Nonce / capability-id replay protection
  main.rs                  End-to-end walkthrough exercising the full protocol
```

## Running it

```bash
# Run the end-to-end protocol walkthrough
cargo run

# Run the unit test suite (17 tests across state machine, authorizer, broker)
cargo test
```

Expected `cargo run` output walks through: reaching T2 via behavioral
continuity, a rejected over-privileged request, a full issue → verify →
derive-key cycle, a blocked replay attempt, a blocked signature-tampering
attempt, and a compromise lockout + recovery reset.

## Requirements

* Rust 2021 edition. Dependency versions in `Cargo.toml` are pinned to remain
  buildable on older stable toolchains (tested on rustc 1.75); newer
  toolchains work too.

## License

MIT — see [`LICENSE`](LICENSE).
