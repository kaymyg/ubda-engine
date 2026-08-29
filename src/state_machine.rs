use crate::types::{BehavioralTelemetry, TrustState};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateMachineError {
    #[error("Invalid transition from {from:?} to {to:?}: {reason}")]
    InvalidTransition {
        from: TrustState,
        to: TrustState,
        reason: String,
    },
    #[error("System is locked in Compromised state (T_-1). Operation rejected.")]
    CompromiseLockout,
}

pub struct SystemStateMachine {
    current_state: TrustState,
    anomaly_threshold: f32,
}

impl SystemStateMachine {
    pub fn new(anomaly_threshold: f32) -> Self {
        Self {
            current_state: TrustState::Unauthenticated,
            anomaly_threshold,
        }
    }

    pub fn current_state(&self) -> TrustState {
        self.current_state
    }

    pub fn handle_device_authenticated(&mut self) -> Result<TrustState, StateMachineError> {
        self.assert_not_compromised()?;
        if self.current_state != TrustState::Unauthenticated {
            return Err(StateMachineError::InvalidTransition {
                from: self.current_state,
                to: TrustState::DeviceAuthenticated,
                reason: "Device authentication is only valid from T0".into(),
            });
        }
        self.current_state = TrustState::DeviceAuthenticated;
        Ok(self.current_state)
    }

    pub fn handle_behavioral_assertion(
        &mut self,
        telemetry: &BehavioralTelemetry,
    ) -> Result<TrustState, StateMachineError> {
        self.assert_not_compromised()?;

        if telemetry.anomaly_score >= self.anomaly_threshold {
            self.trigger_compromise();
            return Err(StateMachineError::CompromiseLockout);
        }

        if self.current_state == TrustState::DeviceAuthenticated && telemetry.anomaly_score < 0.25 {
            self.current_state = TrustState::BehavioralContinuity;
        }
        Ok(self.current_state)
    }

    pub fn handle_step_up_auth(&mut self) -> Result<TrustState, StateMachineError> {
        self.assert_not_compromised()?;
        if self.current_state != TrustState::BehavioralContinuity {
            return Err(StateMachineError::InvalidTransition {
                from: self.current_state,
                to: TrustState::HighAssurance,
                reason: "Step-up authentication requires active T2 state".into(),
            });
        }
        self.current_state = TrustState::HighAssurance;
        Ok(self.current_state)
    }

    pub fn handle_critical_elevation(&mut self) -> Result<TrustState, StateMachineError> {
        self.assert_not_compromised()?;
        if self.current_state != TrustState::HighAssurance {
            return Err(StateMachineError::InvalidTransition {
                from: self.current_state,
                to: TrustState::CriticalElevation,
                reason: "Critical elevation requires active T3 state".into(),
            });
        }
        self.current_state = TrustState::CriticalElevation;
        Ok(self.current_state)
    }

    pub fn trigger_compromise(&mut self) -> TrustState {
        self.current_state = TrustState::Compromised;
        TrustState::Compromised
    }

    pub fn handle_hardware_recovery_reset(&mut self) -> Result<TrustState, StateMachineError> {
        if self.current_state != TrustState::Compromised {
            return Err(StateMachineError::InvalidTransition {
                from: self.current_state,
                to: TrustState::Unauthenticated,
                reason: "Recovery reset is only valid from T_-1 state".into(),
            });
        }
        self.current_state = TrustState::Unauthenticated;
        Ok(self.current_state)
    }

    fn assert_not_compromised(&self) -> Result<(), StateMachineError> {
        if self.current_state == TrustState::Compromised {
            Err(StateMachineError::CompromiseLockout)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low_risk_telemetry() -> BehavioralTelemetry {
        BehavioralTelemetry {
            anomaly_score: 0.05,
            cadence_entropy: 0.95,
            spatial_risk_factor: 0.01,
            timestamp: 0,
        }
    }

    #[test]
    fn starts_unauthenticated() {
        let sm = SystemStateMachine::new(0.7);
        assert_eq!(sm.current_state(), TrustState::Unauthenticated);
    }

    #[test]
    fn full_happy_path_escalation() {
        let mut sm = SystemStateMachine::new(0.7);
        sm.handle_device_authenticated().unwrap();
        assert_eq!(sm.current_state(), TrustState::DeviceAuthenticated);

        sm.handle_behavioral_assertion(&low_risk_telemetry())
            .unwrap();
        assert_eq!(sm.current_state(), TrustState::BehavioralContinuity);

        sm.handle_step_up_auth().unwrap();
        assert_eq!(sm.current_state(), TrustState::HighAssurance);

        sm.handle_critical_elevation().unwrap();
        assert_eq!(sm.current_state(), TrustState::CriticalElevation);
    }

    #[test]
    fn cannot_skip_states() {
        let mut sm = SystemStateMachine::new(0.7);
        assert!(sm.handle_step_up_auth().is_err());
        assert!(sm.handle_critical_elevation().is_err());
    }

    #[test]
    fn high_anomaly_triggers_compromise() {
        let mut sm = SystemStateMachine::new(0.5);
        sm.handle_device_authenticated().unwrap();

        let risky = BehavioralTelemetry {
            anomaly_score: 0.9,
            cadence_entropy: 0.1,
            spatial_risk_factor: 0.8,
            timestamp: 0,
        };
        let result = sm.handle_behavioral_assertion(&risky);
        assert!(matches!(result, Err(StateMachineError::CompromiseLockout)));
        assert_eq!(sm.current_state(), TrustState::Compromised);
    }

    #[test]
    fn compromised_state_blocks_all_transitions_until_reset() {
        let mut sm = SystemStateMachine::new(0.5);
        sm.trigger_compromise();

        assert!(sm.handle_device_authenticated().is_err());
        assert!(sm
            .handle_behavioral_assertion(&low_risk_telemetry())
            .is_err());
        assert!(sm.handle_step_up_auth().is_err());
        assert!(sm.handle_critical_elevation().is_err());

        sm.handle_hardware_recovery_reset().unwrap();
        assert_eq!(sm.current_state(), TrustState::Unauthenticated);
    }

    #[test]
    fn recovery_reset_only_valid_from_compromised() {
        let mut sm = SystemStateMachine::new(0.5);
        assert!(sm.handle_hardware_recovery_reset().is_err());
    }
}
