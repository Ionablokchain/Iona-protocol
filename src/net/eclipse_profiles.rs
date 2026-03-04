//! Eclipse protection profiles for IONA v28.
//!
//! Two profiles:
//!   - `prod`    : strict diversity (min 3 distinct buckets, low caps)
//!   - `testnet` : relaxed (min 1 distinct bucket, higher caps)
//!
//! This does NOT change consensus rules — only P2P connection policy.

use serde::{Deserialize, Serialize};

/// Eclipse protection profile name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EclipseProfile {
    Prod,
    Testnet,
}

impl Default for EclipseProfile {
    fn default() -> Self {
        Self::Testnet
    }
}

impl EclipseProfile {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "prod" | "production" | "mainnet" => Self::Prod,
            _ => Self::Testnet,
        }
    }
}

/// Eclipse protection parameters derived from the profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EclipseParams {
    pub profile: EclipseProfile,
    /// Bucket classification: "ip16" (first 2 octets) or "ip24" (first 3).
    pub bucket_kind: String,
    /// Max inbound connections per bucket.
    pub max_inbound_per_bucket: usize,
    /// Max outbound connections per bucket.
    pub max_outbound_per_bucket: usize,
    /// Minimum distinct buckets required (eclipse detection).
    pub eclipse_detection_min_buckets: usize,
    /// Cooldown before re-seeding peers after eclipse detection (seconds).
    pub reseed_cooldown_s: u64,
    /// Max total connections.
    pub max_connections_total: usize,
    /// Max connections per peer.
    pub max_connections_per_peer: usize,
}

impl EclipseParams {
    pub fn from_profile(profile: EclipseProfile) -> Self {
        match profile {
            EclipseProfile::Prod => Self {
                profile,
                bucket_kind: "ip16".into(),
                max_inbound_per_bucket: 2,
                max_outbound_per_bucket: 2,
                eclipse_detection_min_buckets: 3,
                reseed_cooldown_s: 60,
                max_connections_total: 100,
                max_connections_per_peer: 4,
            },
            EclipseProfile::Testnet => Self {
                profile,
                bucket_kind: "ip16".into(),
                max_inbound_per_bucket: 8,
                max_outbound_per_bucket: 8,
                eclipse_detection_min_buckets: 1,
                reseed_cooldown_s: 120,
                max_connections_total: 200,
                max_connections_per_peer: 8,
            },
        }
    }

    /// Check if current bucket distribution is safe.
    pub fn is_safe(&self, distinct_buckets: usize) -> bool {
        distinct_buckets >= self.eclipse_detection_min_buckets
    }

    /// Human-readable description of the profile.
    pub fn description(&self) -> &str {
        match self.profile {
            EclipseProfile::Prod => "Production: strict diversity (min 3 distinct buckets, low per-bucket caps)",
            EclipseProfile::Testnet => "Testnet: relaxed diversity (min 1 distinct bucket, higher caps)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prod_profile() {
        let p = EclipseParams::from_profile(EclipseProfile::Prod);
        assert_eq!(p.eclipse_detection_min_buckets, 3);
        assert_eq!(p.max_inbound_per_bucket, 2);
        assert!(!p.is_safe(2));
        assert!(p.is_safe(3));
        assert!(p.is_safe(5));
    }

    #[test]
    fn test_testnet_profile() {
        let p = EclipseParams::from_profile(EclipseProfile::Testnet);
        assert_eq!(p.eclipse_detection_min_buckets, 1);
        assert_eq!(p.max_inbound_per_bucket, 8);
        assert!(p.is_safe(1));
        assert!(p.is_safe(5));
    }

    #[test]
    fn test_from_str_loose() {
        assert_eq!(EclipseProfile::from_str_loose("prod"), EclipseProfile::Prod);
        assert_eq!(EclipseProfile::from_str_loose("production"), EclipseProfile::Prod);
        assert_eq!(EclipseProfile::from_str_loose("mainnet"), EclipseProfile::Prod);
        assert_eq!(EclipseProfile::from_str_loose("testnet"), EclipseProfile::Testnet);
        assert_eq!(EclipseProfile::from_str_loose("dev"), EclipseProfile::Testnet);
        assert_eq!(EclipseProfile::from_str_loose("anything"), EclipseProfile::Testnet);
    }

    #[test]
    fn test_profile_descriptions() {
        let prod = EclipseParams::from_profile(EclipseProfile::Prod);
        assert!(prod.description().contains("strict"));
        let testnet = EclipseParams::from_profile(EclipseProfile::Testnet);
        assert!(testnet.description().contains("relaxed"));
    }
}
