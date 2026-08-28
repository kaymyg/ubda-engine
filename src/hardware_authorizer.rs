use crate::types::{
    AccessOperation, DataClassification, DataAccessCapability, EphemeralSessionKey, PolicyAssertion,
    TrustState,
};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, Signature, UnparsedPublicKey, ED25519};
use thiserror::Error;

const MAX_ASSERTION_AGE_SECONDS: i64 = 60;

#[derive(Error, Debug)]
pub enum AuthorizerError {
    #[error("Policy assertion signature is invalid.")]
    InvalidAssertionSignature,
    #[error("Policy assertion is stale or from the future. Current: {current}, asserted: {asserted}")]
    StaleAssertion { current: i64, asserted: i64 },
    #[error("Capability TTL must be positive. Received: {ttl_seconds}")]
    InvalidTtl { ttl_seconds: i64 },
    #[error("Capability expiry overflowed the supported timestamp range.")]
    ExpiryOverflow,
    #[error("Secure randomness generation failed.")]
    RandomnessFailure,
    #[error("Policy state ({asserted:?}) does not satisfy required state ({required:?}) for classification {classification:?}.")]
    InsufficientTrustState { asserted: TrustState, required: TrustState, classification: DataClassification },
    #[error("Key derivation failed.")]
    DerivationFailure,
}

pub trait KeyAuthority {
    fn public_key_bytes(&self) -> &[u8];
    fn issue_dac(
        &self, assertion: &PolicyAssertion, resource_id: String, classification: DataClassification,
        operation: AccessOperation, current_time: i64, ttl_seconds: i64,
    ) -> Result<DataAccessCapability, AuthorizerError>;
    fn derive_session_key(&self, dac: &DataAccessCapability) -> Result<EphemeralSessionKey, AuthorizerError>;
}

/// Software development mock implementing KeyAuthority.
/// DEMO_MASTER_SEED represents hardware root key abstractions for development testing.
pub struct MockHardwareAuthorizer {
    key_pair: Ed25519KeyPair,
    public_key: Vec<u8>,
    trusted_bte_public_key: Vec<u8>,
    demo_master_root_secret: [u8; 32],
}

impl MockHardwareAuthorizer {
    pub fn new(trusted_bte_public_key: &[u8]) -> Self {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("system RNG must be available for the development authorizer");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .expect("generated authorizer key must be valid");
        let public_key = key_pair.public_key().as_ref().to_vec();
        Self { key_pair, public_key, trusted_bte_public_key: trusted_bte_public_key.to_vec(), demo_master_root_secret: [0x55u8; 32] }
    }

    fn verify_assertion(&self, assertion: &PolicyAssertion, current_time: i64) -> Result<(), AuthorizerError> {
        if assertion.timestamp > current_time || current_time - assertion.timestamp > MAX_ASSERTION_AGE_SECONDS {
            return Err(AuthorizerError::StaleAssertion { current: current_time, asserted: assertion.timestamp });
        }
        UnparsedPublicKey::new(&ED25519, &self.trusted_bte_public_key)
            .verify(&assertion.canonical_bytes(), &assertion.bte_signature)
            .map_err(|_| AuthorizerError::InvalidAssertionSignature)
    }
}

impl KeyAuthority for MockHardwareAuthorizer {
    fn public_key_bytes(&self) -> &[u8] { &self.public_key }

    fn issue_dac(
        &self, assertion: &PolicyAssertion, resource_id: String, classification: DataClassification,
        operation: AccessOperation, current_time: i64, ttl_seconds: i64,
    ) -> Result<DataAccessCapability, AuthorizerError> {
        self.verify_assertion(assertion, current_time)?;
        if ttl_seconds <= 0 { return Err(AuthorizerError::InvalidTtl { ttl_seconds }); }
        let expires_at = current_time.checked_add(ttl_seconds).ok_or(AuthorizerError::ExpiryOverflow)?;
        let minimum_state = TrustState::minimum_required_for(classification);
        if assertion.asserted_state < minimum_state {
            return Err(AuthorizerError::InsufficientTrustState { asserted: assertion.asserted_state, required: minimum_state, classification });
        }

        let mut nonce_bytes = [0u8; 8];
        SystemRandom::new().fill(&mut nonce_bytes).map_err(|_| AuthorizerError::RandomnessFailure)?;
        let nonce = u64::from_be_bytes(nonce_bytes);
        let mut dac = DataAccessCapability {
            cap_id: format!("dac_{nonce:016x}"), session_id: assertion.session_id.clone(),
            target_resource_id: resource_id, target_classification: classification, permitted_operation: operation,
            issued_at: current_time, expires_at, nonce, required_state: minimum_state, authorizer_signature: vec![],
        };
        let sig: Signature = self.key_pair.sign(&dac.canonical_bytes());
        dac.authorizer_signature = sig.as_ref().to_vec();
        Ok(dac)
    }

    fn derive_session_key(&self, dac: &DataAccessCapability) -> Result<EphemeralSessionKey, AuthorizerError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &dac.nonce.to_be_bytes());
        let prk = salt.extract(&self.demo_master_root_secret);
        // The signed DAC captures all capability scope; bind it into the derived key.
        let canonical_dac = dac.canonical_bytes();
        let info = [b"ubda/v1/session-key".as_slice(), canonical_dac.as_slice()];
        let okm = prk.expand(&info, hkdf::HKDF_SHA256).map_err(|_| AuthorizerError::DerivationFailure)?;
        let mut key_bytes = [0u8; 32];
        okm.fill(&mut key_bytes).map_err(|_| AuthorizerError::DerivationFailure)?;
        Ok(EphemeralSessionKey { key_bytes, cap_id: dac.cap_id.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bte_interface::BehavioralTrustEngine;
    use crate::types::BehavioralTelemetry;

    fn setup(session_id: &str, state: TrustState) -> (MockHardwareAuthorizer, PolicyAssertion) {
        let bte = BehavioralTrustEngine::new(0.7);
        let authorizer = MockHardwareAuthorizer::new(bte.public_key_bytes());
        let telemetry = BehavioralTelemetry { anomaly_score: 0.05, cadence_entropy: 0.9, spatial_risk_factor: 0.01, timestamp: 0 };
        (authorizer, bte.process_telemetry(session_id, telemetry, state))
    }

    #[test]
    fn issues_dac_when_trust_sufficient() {
        let (authorizer, assertion) = setup("s1", TrustState::BehavioralContinuity);
        assert!(authorizer.issue_dac(&assertion, "doc.enc".to_string(), DataClassification::D1, AccessOperation::Read, 0, 60).is_ok());
    }

    #[test]
    fn rejects_tampered_assertion() {
        let (authorizer, mut assertion) = setup("s1", TrustState::BehavioralContinuity);
        assertion.asserted_state = TrustState::CriticalElevation;
        assert!(matches!(authorizer.issue_dac(&assertion, "doc.enc".to_string(), DataClassification::D1, AccessOperation::Read, 0, 60), Err(AuthorizerError::InvalidAssertionSignature)));
    }

    #[test]
    fn rejects_stale_assertion() {
        let (authorizer, assertion) = setup("s1", TrustState::BehavioralContinuity);
        assert!(matches!(authorizer.issue_dac(&assertion, "doc.enc".to_string(), DataClassification::D1, AccessOperation::Read, 61, 60), Err(AuthorizerError::StaleAssertion { .. })));
    }

    #[test]
    fn rejects_invalid_ttl() {
        let (authorizer, assertion) = setup("s1", TrustState::BehavioralContinuity);
        assert!(matches!(authorizer.issue_dac(&assertion, "doc.enc".to_string(), DataClassification::D1, AccessOperation::Read, 0, 0), Err(AuthorizerError::InvalidTtl { .. })));
    }

    #[test]
    fn rejects_dac_when_trust_insufficient() {
        let (authorizer, assertion) = setup("s1", TrustState::DeviceAuthenticated);
        assert!(matches!(authorizer.issue_dac(&assertion, "vault_seed".to_string(), DataClassification::D3, AccessOperation::Read, 0, 60), Err(AuthorizerError::InsufficientTrustState { .. })));
    }

    #[test]
    fn derived_keys_bind_the_capability_scope() {
        let (authorizer, assertion) = setup("s1", TrustState::BehavioralContinuity);
        let dac_a = authorizer.issue_dac(&assertion, "a.enc".to_string(), DataClassification::D1, AccessOperation::Read, 0, 60).unwrap();
        let mut dac_b = dac_a.clone();
        dac_b.session_id = "different-session".to_string();
        assert_ne!(authorizer.derive_session_key(&dac_a).unwrap().key_bytes, authorizer.derive_session_key(&dac_b).unwrap().key_bytes);
    }
}
