use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustState {
    Compromised = -1,         // T_-1: Hard Isolation / Containment
    Unauthenticated = 0,      // T_0: Unauthenticated / Raw Boot
    DeviceAuthenticated = 1,  // T_1: Hardened Device Access
    BehavioralContinuity = 2, // T_2: BTE Telemetry Verified
    HighAssurance = 3,        // T_3: Biometric / Step-Up Verified
    CriticalElevation = 4,    // T_4: Out-of-Band / Hardware Token
}

impl TrustState {
    /// Enforces the minimum trust state required for each data classification level.
    pub fn minimum_required_for(classification: DataClassification) -> Self {
        match classification {
            DataClassification::D0 => TrustState::DeviceAuthenticated, // D0 -> T1
            DataClassification::D1 => TrustState::BehavioralContinuity, // D1 -> T2
            DataClassification::D2 => TrustState::HighAssurance,       // D2 -> T3
            DataClassification::D3 => TrustState::CriticalElevation,   // D3 -> T4
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClassification {
    D0, // Public / System Shell
    D1, // Standard Personal Data
    D2, // Sensitive / Financial / Health
    D3, // Master Keys / Root Credentials
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessOperation {
    Read,
    Write,
    Execute,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralTelemetry {
    pub anomaly_score: f32,
    pub cadence_entropy: f32,
    pub spatial_risk_factor: f32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAssertion {
    pub session_id: String,
    pub asserted_state: TrustState,
    pub telemetry_proof: BehavioralTelemetry,
    pub timestamp: i64,
}

/// Signed Data Access Capability (DAC)
/// Note: Ed25519 is utilized as a development placeholder for Post-Quantum signature algorithms (e.g., ML-DSA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAccessCapability {
    pub cap_id: String,
    pub session_id: String,
    pub target_resource_id: String,
    pub target_classification: DataClassification,
    pub permitted_operation: AccessOperation,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: u64,
    pub required_state: TrustState,
    pub authorizer_signature: Vec<u8>,
}

impl DataAccessCapability {
    /// Canonical binary serialization ensuring signature coverage across all envelope fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.authorizer_signature.clear();
        bincode::serialize(&clone).expect("Canonical serialization failed")
    }
}

/// ZeroizeOnDrop cleans volatile memory on drop; it does not dictate external memory isolation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSessionKey {
    pub key_bytes: [u8; 32],
    pub cap_id: String,
}
