# UBDA V1.2-alpha — Architectural Reference

## 1. Core principles

* **Hardware boundary of authority** — a software behavioral engine may adjust
  dynamic trust metrics, but no software component possesses the authority or
  cryptographic material to derive keys or release protected data
  independently.
* **Capability-scoped execution** — protected keys are ephemeral and bound
  strictly to the target resource, permitted operation, classification level,
  TTL, and non-replayable nonce defined in a signed Data Access Capability
  (DAC).
* **Metadata & payload uniformity** — at rest, both file payloads and
  structural metadata are treated as cryptographically indistinguishable from
  noise (an at-rest design goal this prototype does not itself implement).

## 2. Dynamic trust-state matrix

```
                            ┌─────────────────────────┐
                            │    T-1: COMPROMISED     │
                            └────────────▲────────────┘
                                         │ Hardware Reset / Reset to T0
   ┌─────────────────────────────────────┴─────────────────────────────────────┐
   │                                                                           │
┌──┴──┐  Device Auth ┌─────┐  BTE Assertion ┌─────┐  Step-Up Auth ┌─────┐ Out-of-Band ┌─────┐
│ T0  ├─────────────►│ T1  ├───────────────►│ T2  ├──────────────►│ T3  ├───────────►│ T4  │
└─────┘              └─────┘                └─────┘                └─────┘            └─────┘
 Cold                Public /              Personal               Sensitive          Critical
 Boot                System                Data (D1)              Records            Master
                     Shell (D0)                                   (D2)               Keys (D3)
```

| Trust State | Name | Minimum Gatekeeper Requirement | Accessible Data Classification |
| --- | --- | --- | --- |
| `T-1` | Compromised | Hard anomaly / system intrusion interrupt | None — active keys revoked, state frozen |
| `T0` | Unauthenticated | Cold boot / sealed state | None — all payload & metadata encrypted |
| `T1` | Device Authenticated | Hardware-backed passkey / attestation | `D0` — OS shell, public binaries, non-sensitive configs |
| `T2` | Behavioral Continuity | Validated telemetry (`T1` + BTE assertion) | `D1` — standard personal files, documents |
| `T3` | High Assurance | Hardware biometric / local PIN (`T2` + step-up) | `D2` — financial, medical, private records |
| `T4` | Critical Elevation | Hardware HSM / out-of-band token (`T3` + elevation) | `D3` — root signing keys, master vault seeds |

## 3. System architecture & component isolation

```
                           ┌───────────────────────────┐
                           │      USER INTERACTION     │
                           └─────────────┬─────────────┘
                                         │
                                         ▼
  UNTRUSTED SOFTWARE DOMAIN              │
 ┌───────────────────────────────────────┼───────────────────────────────────────────┐
 │                                       ▼                                           │
 │                            ┌────────────────────┐                                 │
 │                            │ BEHAVIOURAL TRUST  │ ── Processes Telemetry Vectors  │
 │                            │    ENGINE (BTE)    │    (No direct key access)       │
 │                            └──────────┬─────────┘                                 │
 │                                       │ Policy Assertion                          │
 │                                       ▼                                           │
 │                            ┌────────────────────┐                                 │
 │                            │  REFERENCE MONITOR │ ── Requests capability          │
 │                            │  & POLICY ENGINE   │    and evaluates operations       │
 │                            └──────────┬─────────┘                                 │
 └───────────────────────────────────────┼───────────────────────────────────────────┘
                                   Authorization
                                      Request
 HARDWARE / TEE TRUST DOMAIN             │
 ┌───────────────────────────────────────┼───────────────────────────────────────────┐
 │                                       ▼                                           │
 │                            ┌────────────────────┐                                 │
 │                            │   KEY AUTHORITY    │ ── Validates Trust State &      │
 │                            │   (Hardware / TEE) │    Signs Canonical DAC          │
 │                            └──────────┬─────────┘                                 │
 │                                       │ Signed DAC                                │
 │                                       ▼                                           │
 │                            ┌────────────────────┐                                 │
 │                            │     KEY BROKER     │ ── Checks Signatures, Anti-    │
 │                            │ (Execution Boundary)│    Replay, & Derives Ephemeral │
 │                            └──────────┬─────────┘    Session Key ($K_{eph}$)      │
 └───────────────────────────────────────┼───────────────────────────────────────────┘
                                   Ephemeral Key
                                         │
                                         ▼
                             ┌──────────────────────┐
                             │ PLAINTEXT EXECUTION  │
                             │   (RAM Ephemeral)    │
                             └──────────────────────┘
```

## 4. Where the code maps to the diagram

| Diagram component | Source file |
| --- | --- |
| Behavioural Trust Engine | `src/bte_interface.rs` |
| Reference Monitor / trust-state transitions | `src/state_machine.rs` |
| Key Authority (hardware/TEE) | `src/hardware_authorizer.rs` |
| Key Broker (execution boundary, anti-replay) | `src/key_broker.rs`, `src/replay_store.rs` |
| Shared types (DAC, telemetry, trust/classification enums) | `src/types.rs` |

## 5. Known simplifications in this prototype

* `MockHardwareAuthorizer` runs in the same process as everything else — a
  real implementation would put the `KeyAuthority` behind a TEE/HSM boundary
  with no shared address space.
* The "demo master root secret" is a fixed byte array for reproducibility in
  tests/demos; a real system would provision this from hardware-backed key
  storage and never expose it to software.
* At-rest payload/metadata encryption (Invariant 3) is described but not
  implemented here — this prototype focuses on the trust-state machine and
  capability lifecycle.
