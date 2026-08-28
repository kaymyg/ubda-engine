mod bte_interface;
mod hardware_authorizer;
mod key_broker;
mod replay_store;
mod state_machine;
mod types;

use bte_interface::BehavioralTrustEngine;
use hardware_authorizer::{KeyAuthority, MockHardwareAuthorizer};
use key_broker::KeyBroker;
use state_machine::SystemStateMachine;
use types::*;

fn main() {
    println!("=== UBDA V1.2-alpha Architectural Refactor Integration Test ===");

    let mut state_machine = SystemStateMachine::new(0.70);
    let bte = BehavioralTrustEngine::new(0.70);
    let mock_authorizer = MockHardwareAuthorizer::new(bte.public_key_bytes());
    let mut key_broker = KeyBroker::new(&mock_authorizer);

    let session_id = "sess_ubda_v1_alpha";
    let now = chrono::Utc::now().timestamp();

    // 1. Establish State T0 -> T1 -> T2
    println!("\n[1/6] Transitioning State: T0 -> T1 -> T2...");
    state_machine.handle_device_authenticated().unwrap();

    let telemetry = BehavioralTelemetry {
        anomaly_score: 0.10,
        cadence_entropy: 0.90,
        spatial_risk_factor: 0.02,
        timestamp: now,
    };

    let assertion = bte.process_telemetry(session_id, telemetry.clone(), state_machine.current_state());
    state_machine.handle_behavioral_assertion(&telemetry).unwrap();

    assert_eq!(state_machine.current_state(), TrustState::BehavioralContinuity);
    println!(" -> Active State: T2 (BehavioralContinuity)");

    // 2. Reject Insufficient Classification (T2 requesting D2 data)
    println!("\n[2/6] Testing Classification Policy Enforcement (T2 requesting D2 data)...");
    let d2_issuance = mock_authorizer.issue_dac(
        &assertion,
        "financial_records.enc".to_string(),
        DataClassification::D2, // Requires T3
        AccessOperation::Read,
        now,
        300,
    );

    match d2_issuance {
        Err(hardware_authorizer::AuthorizerError::InsufficientTrustState { .. }) => {
            println!(" -> PASS: Authorizer blocked D2 issuance under T2 trust level.");
        }
        _ => panic!(" -> FAIL: D2 capability improperly issued under T2 state!"),
    }

    // 3. Valid D1 Capability Cycle
    println!("\n[3/6] Issuing & Consuming Valid D1 Capability...");
    let valid_dac = mock_authorizer
        .issue_dac(
            &assertion,
            "personal_document.enc".to_string(),
            DataClassification::D1, // Requires T2
            AccessOperation::Read,
            now,
            300,
        )
        .expect("D1 DAC issuance failed");

    let key = key_broker
        .execute_key_use(&valid_dac, session_id, AccessOperation::Read, now, state_machine.current_state())
        .expect("Key derivation failed");

    println!(" -> PASS: Derived Ephemeral Key (Digest: {:?})", &key.key_bytes[0..4]);

    // 4. Anti-Replay Enforcement
    println!("\n[4/6] Testing Replay Defense...");
    let replay_result = key_broker.execute_key_use(
        &valid_dac,
        session_id,
        AccessOperation::Read,
        now + 1,
        state_machine.current_state(),
    );

    match replay_result {
        Err(key_broker::KeyBrokerError::ReplayDetected) => {
            println!(" -> PASS: Key Broker blocked consumed DAC replay attempt.");
        }
        _ => panic!(" -> FAIL: Replayed DAC was accepted!"),
    }

    // 5. Signature Tamper Verification
    println!("\n[5/6] Testing Signature Integrity Verification...");
    let mut tampered_dac = mock_authorizer
        .issue_dac(
            &assertion,
            "personal_document_2.enc".to_string(),
            DataClassification::D1,
            AccessOperation::Read,
            now,
            300,
        )
        .unwrap();

    // Field modification by attacker
    tampered_dac.required_state = TrustState::CriticalElevation;

    let tamper_result = key_broker.execute_key_use(
        &tampered_dac,
        session_id,
        AccessOperation::Read,
        now,
        TrustState::CriticalElevation,
    );

    match tamper_result {
        Err(key_broker::KeyBrokerError::InvalidSignature) => {
            println!(" -> PASS: Key Broker detected field modification via canonical verification.");
        }
        _ => panic!(" -> FAIL: Tampered capability signature validated!"),
    }

    // 6. Hard Anomaly Lockout & Controlled Recovery
    println!("\n[6/6] Injecting Hard Anomaly Interrupt (T_-1 Lockout)...");
    state_machine.trigger_compromise();
    assert_eq!(state_machine.current_state(), TrustState::Compromised);

    assert!(state_machine.handle_device_authenticated().is_err());
    println!(" -> PASS: Escalation blocked in T_-1 state.");

    state_machine.handle_hardware_recovery_reset().unwrap();
    assert_eq!(state_machine.current_state(), TrustState::Unauthenticated);
    println!(" -> PASS: System performed clean hardware recovery to T0 state.");

    println!("\n=== ALL UBDA V1.2-alpha PROTOCOL TESTS COMPLETED ===");
}
