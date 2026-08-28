use crate::types::{BehavioralTelemetry, PolicyAssertion, TrustState};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub struct BehavioralTrustEngine {
    anomaly_threshold: f32,
    key_pair: Ed25519KeyPair,
}

impl BehavioralTrustEngine {
    pub fn new(anomaly_threshold: f32) -> Self {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("system RNG must be available for the development BTE");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .expect("generated BTE key must be valid");
        Self { anomaly_threshold, key_pair }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    pub fn process_telemetry(
        &self,
        session_id: &str,
        telemetry: BehavioralTelemetry,
        current_state: TrustState,
    ) -> PolicyAssertion {
        let inferred_state = if telemetry.anomaly_score >= self.anomaly_threshold {
            TrustState::Compromised
        } else if telemetry.anomaly_score < 0.20 && current_state == TrustState::DeviceAuthenticated {
            TrustState::BehavioralContinuity
        } else {
            current_state
        };

        let timestamp = telemetry.timestamp;
        let mut assertion = PolicyAssertion {
            session_id: session_id.to_string(),
            asserted_state: inferred_state,
            telemetry_proof: telemetry,
            timestamp,
            bte_signature: vec![],
        };
        assertion.bte_signature = self.key_pair.sign(&assertion.canonical_bytes()).as_ref().to_vec();
        assertion
    }
}
