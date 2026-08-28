use crate::types::{BehavioralTelemetry, PolicyAssertion, TrustState};

pub struct BehavioralTrustEngine {
    anomaly_threshold: f32,
}

impl BehavioralTrustEngine {
    pub fn new(anomaly_threshold: f32) -> Self {
        Self { anomaly_threshold }
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

        PolicyAssertion {
            session_id: session_id.to_string(),
            asserted_state: inferred_state,
            telemetry_proof: telemetry,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}
