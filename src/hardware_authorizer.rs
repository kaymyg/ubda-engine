use crate::types::{
    AccessOperation, DataAccessCapability, DataClassification, EphemeralSessionKey,
    PolicyAssertion, TrustState,
};
use ring::hkdf;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, Signature};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizerError {
    #[error("Policy state ({asserted:?}) does not satisfy required state ({required:?}) for classification {classification:?}.")]
    InsufficientTrustState {
        asserted: TrustState,
        required: TrustState,
        classification: DataClassification,
    },
    #[error("Signature generation failed.")]
    // Ring's Ed25519 signing is currently infallible, so this variant isn't reachable yet.
    // It's kept for forward compatibility with a fallible hardware/HSM or PQC signer.
    #[allow(dead_code)]
    SigningFailure,
    #[error("Key derivation failed.")]
    DerivationFailure,
}

pub trait KeyAuthority {
    fn public_key_bytes(&self) -> &[u8];

    // 8 args mirrors the signed DAC envelope's field set (resource, classification,
    // operation, timing, nonce) one-to-one; a request-object refactor is tracked as a
    // possible future cleanup, not urgent for a prototype of this size.
    #[allow(clippy::too_many_arguments)]
    fn issue_dac(
        &self,
        assertion: &PolicyAssertion,
        resource_id: String,
        classification: DataClassification,
        operation: AccessOperation,
        current_time: i64,
        ttl_seconds: i64,
        nonce: u64,
    ) -> Result<DataAccessCapability, AuthorizerError>;

    fn derive_session_key(
        &self,
        dac: &DataAccessCapability,
    ) -> Result<EphemeralSessionKey, AuthorizerError>;
}

/// Software development mock implementing KeyAuthority.
/// DEMO_MASTER_SEED represents hardware root key abstractions for development testing.
pub struct MockHardwareAuthorizer {
    key_pair: Ed25519KeyPair,
    pub public_key: Vec<u8>,
    demo_master_root_secret: [u8; 32],
}

impl MockHardwareAuthorizer {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();

        Self {
            key_pair,
            public_key,
            demo_master_root_secret: [0x55u8; 32],
        }
    }
}

impl Default for MockHardwareAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyAuthority for MockHardwareAuthorizer {
    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_dac(
        &self,
        assertion: &PolicyAssertion,
        resource_id: String,
        classification: DataClassification,
        operation: AccessOperation,
        current_time: i64,
        ttl_seconds: i64,
        nonce: u64,
    ) -> Result<DataAccessCapability, AuthorizerError> {
        let minimum_state = TrustState::minimum_required_for(classification);

        if assertion.asserted_state < minimum_state {
            return Err(AuthorizerError::InsufficientTrustState {
                asserted: assertion.asserted_state,
                required: minimum_state,
                classification,
            });
        }

        let mut dac = DataAccessCapability {
            cap_id: format!("dac_{}", nonce),
            session_id: assertion.session_id.clone(),
            target_resource_id: resource_id,
            target_classification: classification,
            permitted_operation: operation,
            issued_at: current_time,
            expires_at: current_time + ttl_seconds,
            nonce,
            required_state: minimum_state,
            authorizer_signature: vec![],
        };

        let canonical = dac.canonical_bytes();
        let sig: Signature = self.key_pair.sign(&canonical);
        dac.authorizer_signature = sig.as_ref().to_vec();

        Ok(dac)
    }

    fn derive_session_key(
        &self,
        dac: &DataAccessCapability,
    ) -> Result<EphemeralSessionKey, AuthorizerError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &dac.nonce.to_be_bytes());
        let prk = salt.extract(&self.demo_master_root_secret);
        let info = [dac.target_resource_id.as_bytes(), dac.cap_id.as_bytes()];
        let okm = prk
            .expand(&info, hkdf::HKDF_SHA256)
            .map_err(|_| AuthorizerError::DerivationFailure)?;

        let mut key_bytes = [0u8; 32];
        okm.fill(&mut key_bytes).unwrap();

        Ok(EphemeralSessionKey {
            key_bytes,
            cap_id: dac.cap_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bte_interface::BehavioralTrustEngine;

    fn low_risk_assertion(session_id: &str, state: TrustState) -> PolicyAssertion {
        let bte = BehavioralTrustEngine::new(0.7);
        let telemetry = crate::types::BehavioralTelemetry {
            anomaly_score: 0.05,
            cadence_entropy: 0.9,
            spatial_risk_factor: 0.01,
            timestamp: 0,
        };
        bte.process_telemetry(session_id, telemetry, state)
    }

    #[test]
    fn issues_dac_when_trust_sufficient() {
        let authorizer = MockHardwareAuthorizer::new();
        let assertion = low_risk_assertion("s1", TrustState::BehavioralContinuity);

        let dac = authorizer.issue_dac(
            &assertion,
            "doc.enc".to_string(),
            DataClassification::D1,
            AccessOperation::Read,
            0,
            60,
            1,
        );
        assert!(dac.is_ok());
    }

    #[test]
    fn rejects_dac_when_trust_insufficient() {
        let authorizer = MockHardwareAuthorizer::new();
        let assertion = low_risk_assertion("s1", TrustState::DeviceAuthenticated);

        let dac = authorizer.issue_dac(
            &assertion,
            "vault_seed".to_string(),
            DataClassification::D3, // requires T4
            AccessOperation::Read,
            0,
            60,
            1,
        );
        assert!(matches!(
            dac,
            Err(AuthorizerError::InsufficientTrustState { .. })
        ));
    }

    #[test]
    fn derived_keys_differ_by_nonce_and_resource() {
        let authorizer = MockHardwareAuthorizer::new();
        let assertion = low_risk_assertion("s1", TrustState::BehavioralContinuity);

        let dac_a = authorizer
            .issue_dac(
                &assertion,
                "a.enc".to_string(),
                DataClassification::D1,
                AccessOperation::Read,
                0,
                60,
                1,
            )
            .unwrap();
        let dac_b = authorizer
            .issue_dac(
                &assertion,
                "b.enc".to_string(),
                DataClassification::D1,
                AccessOperation::Read,
                0,
                60,
                2,
            )
            .unwrap();

        let key_a = authorizer.derive_session_key(&dac_a).unwrap();
        let key_b = authorizer.derive_session_key(&dac_b).unwrap();
        assert_ne!(key_a.key_bytes, key_b.key_bytes);
    }

    #[test]
    fn same_dac_derives_deterministic_key() {
        let authorizer = MockHardwareAuthorizer::new();
        let assertion = low_risk_assertion("s1", TrustState::BehavioralContinuity);
        let dac = authorizer
            .issue_dac(
                &assertion,
                "a.enc".to_string(),
                DataClassification::D1,
                AccessOperation::Read,
                0,
                60,
                1,
            )
            .unwrap();

        let key1 = authorizer.derive_session_key(&dac).unwrap();
        let key2 = authorizer.derive_session_key(&dac).unwrap();
        assert_eq!(key1.key_bytes, key2.key_bytes);
    }
}
