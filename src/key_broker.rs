use crate::hardware_authorizer::KeyAuthority;
use crate::replay_store::ReplayStore;
use crate::types::{AccessOperation, DataAccessCapability, EphemeralSessionKey, TrustState};
use ring::signature::{UnparsedPublicKey, ED25519};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyBrokerError {
    #[error("Invalid capability signature or canonical payload tampered.")]
    InvalidSignature,
    #[error("Time bounds invalid. Current: {current}, Issued: {issued}, Expires: {expires}")]
    InvalidTimeBounds { current: i64, issued: i64, expires: i64 },
    #[error("Capability replayed! Cap ID or nonce consumed.")]
    ReplayDetected,
    #[error("Operation requested ({requested:?}) does not match DAC permission ({permitted:?}).")]
    OperationMismatch { requested: AccessOperation, permitted: AccessOperation },
    #[error("System trust state ({current:?}) is lower than required DAC state ({required:?}).")]
    StateRequirementNotMet { current: TrustState, required: TrustState },
    #[error("Session ID mismatch. Key Broker bound to {expected}, DAC issued to {found}.")]
    SessionMismatch { expected: String, found: String },
    #[error("Underlying Key Authority error.")]
    AuthorityError,
}

pub struct KeyBroker<'a> {
    authorizer: &'a dyn KeyAuthority,
    replay_store: ReplayStore,
}

impl<'a> KeyBroker<'a> {
    pub fn new(authorizer: &'a dyn KeyAuthority) -> Self {
        Self {
            authorizer,
            replay_store: ReplayStore::new(),
        }
    }

    pub fn execute_key_use(
        &mut self,
        dac: &DataAccessCapability,
        bound_session_id: &str,
        requested_op: AccessOperation,
        current_time: i64,
        system_state: TrustState,
    ) -> Result<EphemeralSessionKey, KeyBrokerError> {
        if dac.session_id != bound_session_id {
            return Err(KeyBrokerError::SessionMismatch {
                expected: bound_session_id.to_string(),
                found: dac.session_id.clone(),
            });
        }

        if current_time < dac.issued_at || current_time >= dac.expires_at {
            return Err(KeyBrokerError::InvalidTimeBounds {
                current: current_time,
                issued: dac.issued_at,
                expires: dac.expires_at,
            });
        }

        if system_state == TrustState::Compromised || system_state < dac.required_state {
            return Err(KeyBrokerError::StateRequirementNotMet {
                current: system_state,
                required: dac.required_state,
            });
        }

        if dac.permitted_operation != requested_op {
            return Err(KeyBrokerError::OperationMismatch {
                requested: requested_op,
                permitted: dac.permitted_operation,
            });
        }

        let peer_public_key = UnparsedPublicKey::new(&ED25519, self.authorizer.public_key_bytes());
        let canonical_bytes = dac.canonical_bytes();

        peer_public_key
            .verify(&canonical_bytes, &dac.authorizer_signature)
            .map_err(|_| KeyBrokerError::InvalidSignature)?;

        // Only an authentic capability may consume replay state. Registering a
        // capability before signature verification lets a forged request block
        // the valid capability with the same cap ID and nonce.
        if !self.replay_store.check_and_register(&dac.cap_id, &dac.session_id, dac.nonce) {
            return Err(KeyBrokerError::ReplayDetected);
        }

        self.authorizer
            .derive_session_key(dac)
            .map_err(|_| KeyBrokerError::AuthorityError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bte_interface::BehavioralTrustEngine;
    use crate::hardware_authorizer::MockHardwareAuthorizer;
    use crate::types::{BehavioralTelemetry, DataClassification};

    fn setup() -> (MockHardwareAuthorizer, DataAccessCapability, i64, &'static str) {
        let authorizer = MockHardwareAuthorizer::new();
        let bte = BehavioralTrustEngine::new(0.7);
        let session_id = "test_session";
        let now = 1_000_000;

        let telemetry = BehavioralTelemetry {
            anomaly_score: 0.05,
            cadence_entropy: 0.9,
            spatial_risk_factor: 0.01,
            timestamp: now,
        };
        let assertion = bte.process_telemetry(session_id, telemetry, TrustState::DeviceAuthenticated);

        let dac = authorizer
            .issue_dac(
                &assertion,
                "resource.enc".to_string(),
                DataClassification::D1,
                AccessOperation::Read,
                now,
                300,
                42,
            )
            .unwrap();

        (authorizer, dac, now, session_id)
    }

    #[test]
    fn valid_capability_derives_key() {
        let (authorizer, dac, now, session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        let result = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Read,
            now,
            TrustState::BehavioralContinuity,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn replay_is_rejected() {
        let (authorizer, dac, now, session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        broker
            .execute_key_use(&dac, session_id, AccessOperation::Read, now, TrustState::BehavioralContinuity)
            .unwrap();

        let replay = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Read,
            now + 1,
            TrustState::BehavioralContinuity,
        );
        assert!(matches!(replay, Err(KeyBrokerError::ReplayDetected)));
    }

    #[test]
    fn invalid_signature_does_not_consume_replay_state() {
        let (authorizer, dac, now, session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        let mut forged_dac = dac.clone();
        forged_dac.required_state = TrustState::CriticalElevation;

        let forged_result = broker.execute_key_use(
            &forged_dac,
            session_id,
            AccessOperation::Read,
            now,
            TrustState::CriticalElevation,
        );
        assert!(matches!(forged_result, Err(KeyBrokerError::InvalidSignature)));

        let valid_result = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Read,
            now,
            TrustState::BehavioralContinuity,
        );
        assert!(valid_result.is_ok());
    }

    #[test]
    fn tampered_capability_fails_signature_check() {
        let (authorizer, mut dac, now, session_id) = setup();
        dac.required_state = TrustState::CriticalElevation;

        let mut broker = KeyBroker::new(&authorizer);
        let result = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Read,
            now,
            TrustState::CriticalElevation,
        );
        assert!(matches!(result, Err(KeyBrokerError::InvalidSignature)));
    }

    #[test]
    fn insufficient_trust_state_is_rejected() {
        let (authorizer, dac, now, session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        let result = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Read,
            now,
            TrustState::DeviceAuthenticated, // below required T2
        );
        assert!(matches!(result, Err(KeyBrokerError::StateRequirementNotMet { .. })));
    }

    #[test]
    fn expired_capability_is_rejected() {
        let (authorizer, dac, now, session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        let result = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Read,
            now + 301, // past TTL
            TrustState::BehavioralContinuity,
        );
        assert!(matches!(result, Err(KeyBrokerError::InvalidTimeBounds { .. })));
    }

    #[test]
    fn wrong_operation_is_rejected() {
        let (authorizer, dac, now, session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        let result = broker.execute_key_use(
            &dac,
            session_id,
            AccessOperation::Write, // DAC was issued for Read
            now,
            TrustState::BehavioralContinuity,
        );
        assert!(matches!(result, Err(KeyBrokerError::OperationMismatch { .. })));
    }

    #[test]
    fn session_mismatch_is_rejected() {
        let (authorizer, dac, now, _session_id) = setup();
        let mut broker = KeyBroker::new(&authorizer);
        let result = broker.execute_key_use(
            &dac,
            "different_session",
            AccessOperation::Read,
            now,
            TrustState::BehavioralContinuity,
        );
        assert!(matches!(result, Err(KeyBrokerError::SessionMismatch { .. })));
    }
}
