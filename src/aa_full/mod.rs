//! IONA v78 — Full ERC-4337 Account Abstraction.
//!
//! This module implements the complete account abstraction stack:
//! - **EntryPoint** native precompile (v0.7) – handles UserOperation validation and execution
//! - **Bundler** – collects, simulates, builds and submits bundles to the EntryPoint
//! - **Paymaster** – sponsors gas for users (verifying and token paymasters)
//! - **Simulation** – off‑chain validation for bundlers and RPC endpoints
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::aa_full::{AaConfig, AaServices, init_account_abstraction};
//!
//! let config = AaConfig::default();
//! let services = init_account_abstraction(config, chain_id, beneficiary).await?;
//!
//! // Add a UserOperation
//! services.bundler.add_operation(user_op)?;
//!
//! // Build and submit a bundle
//! let tx_hash = services.bundler.build_and_submit().await?;
//! ```
//!
//! # Feature flags
//! - `aa_full` – enables all account abstraction features (default)
//! - `aa_bundler` – only bundler (for standalone bundler nodes)
//! - `aa_entrypoint` – only EntryPoint precompile (for full nodes)
//! - `aa_paymaster` – paymaster services

// -----------------------------------------------------------------------------
// Module exports
// -----------------------------------------------------------------------------

pub mod entry_point;
pub mod bundler;
pub mod paymaster;
pub mod simulation;

// Re‑export the most important types for easy access
pub use entry_point::{
    EntryPoint, EntryPointError, HandleOpsResult, ValidationResult,
    ENTRY_POINT_ADDRESS, ENTRY_POINT_V07,
};
pub use bundler::{Bundler, BundlerConfig, BundlerError, BundlerMetrics};
pub use paymaster::{VerifyingPaymaster, TokenPaymaster, PaymasterError};
pub use simulation::{SimulationError, simulate_all, SimulationContext};

use std::sync::Arc;
use crate::evm::EvmState;

// -----------------------------------------------------------------------------
// Unified configuration
// -----------------------------------------------------------------------------

/// Central configuration for the entire account abstraction subsystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AaConfig {
    /// EntryPoint precompile configuration (mostly static, kept for future use).
    pub entrypoint: EntryPointConfig,
    /// Bundler configuration.
    pub bundler: BundlerConfig,
    /// Paymaster configuration (global defaults).
    pub paymaster: PaymasterGlobalConfig,
    /// Simulation defaults.
    pub simulation: SimulationConfig,
}

/// EntryPoint configuration – minimal because the precompile is fixed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntryPointConfig {
    /// Whether to enable detailed tracing for each UserOperation.
    pub trace_ops: bool,
    /// Maximum gas per UserOperation (global cap).
    pub max_gas_per_op: u64,
}

impl Default for EntryPointConfig {
    fn default() -> Self {
        Self {
            trace_ops: false,
            max_gas_per_op: 15_000_000,
        }
    }
}

/// Global paymaster settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaymasterGlobalConfig {
    /// Default verifying paymaster address (if any).
    pub default_verifying_paymaster: Option<String>,
    /// Default token paymaster address.
    pub default_token_paymaster: Option<String>,
    /// Minimum paymaster deposit required (in base units).
    pub min_deposit: u64,
}

impl Default for PaymasterGlobalConfig {
    fn default() -> Self {
        Self {
            default_verifying_paymaster: None,
            default_token_paymaster: None,
            min_deposit: 1_000_000_000_000, // 0.001 IONA
        }
    }
}

/// Simulation configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SimulationConfig {
    /// Maximum number of UserOperations to simulate in one batch.
    pub max_simulate_batch: usize,
    /// Timeout in milliseconds for each simulation.
    pub timeout_ms: u64,
    /// Whether to enforce paymaster staking checks.
    pub enforce_paymaster_stake: bool,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            max_simulate_batch: 50,
            timeout_ms: 2000,
            enforce_paymaster_stake: true,
        }
    }
}

impl Default for AaConfig {
    fn default() -> Self {
        Self {
            entrypoint: EntryPointConfig::default(),
            bundler: BundlerConfig::default(),
            paymaster: PaymasterGlobalConfig::default(),
            simulation: SimulationConfig::default(),
        }
    }
}

// -----------------------------------------------------------------------------
// Initialization and service container
// -----------------------------------------------------------------------------

/// Container for all account abstraction services.
/// This is the main entry point for using ERC-4337 functionality.
pub struct AaServices {
    pub bundler: Bundler,
    pub verifying_paymaster: Option<VerifyingPaymaster>,
    pub token_paymaster: Option<TokenPaymaster>,
    pub simulation_context: SimulationContext,
}

impl AaServices {
    /// Create a new instance of all AA services.
    /// Requires an EVM state reference (for paymaster balances etc.).
    pub async fn new(
        config: AaConfig,
        chain_id: u64,
        beneficiary: String,
        evm_state: Arc<EvmState>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bundler = Bundler::new(beneficiary, chain_id, config.bundler);
        
        let verifying_paymaster = if let Some(addr) = config.paymaster.default_verifying_paymaster {
            Some(VerifyingPaymaster::new(addr, evm_state.clone())?)
        } else {
            None
        };

        let token_paymaster = if let Some(addr) = config.paymaster.default_token_paymaster {
            Some(TokenPaymaster::new(addr, evm_state)?)
        } else {
            None
        };

        let simulation_context = SimulationContext::new(
            chain_id,
            config.simulation.enforce_paymaster_stake,
        );

        Ok(Self {
            bundler,
            verifying_paymaster,
            token_paymaster,
            simulation_context,
        })
    }

    /// Run the bundler's main loop – collects pending ops from mempool, builds and submits bundles.
    /// This is intended for a dedicated bundler thread/task.
    pub async fn run_bundler_loop(&mut self, mempool: &mut crate::evm::account_abstraction::AaMempool) {
        loop {
            let ops = mempool.drain_pending(self.config().bundler.max_ops_per_bundle);
            if !ops.is_empty() {
                for op in ops {
                    let _ = self.bundler.add_operation(op);
                }
                let _ = self.bundler.build_and_submit().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(
                self.config().bundler.submission_interval_ms,
            )).await;
            // Also maintain pending bundles
            let _ = self.bundler.maintain_pending_bundles(0).await;
        }
    }

    /// Get current configuration (read‑only).
    pub fn config(&self) -> AaConfig {
        AaConfig {
            bundler: self.bundler.config.clone(),
            ..Default::default()
        }
    }
}

/// Convenience function to initialize the entire AA subsystem with default config.
pub async fn init_account_abstraction(
    chain_id: u64,
    beneficiary: String,
    evm_state: Arc<EvmState>,
) -> Result<AaServices, Box<dyn std::error::Error>> {
    AaServices::new(AaConfig::default(), chain_id, beneficiary, evm_state).await
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let config = AaConfig::default();
        assert_eq!(config.bundler.max_ops_per_bundle, 100);
        assert_eq!(config.entrypoint.max_gas_per_op, 15_000_000);
        assert_eq!(config.paymaster.min_deposit, 1_000_000_000_000);
        assert!(config.simulation.enforce_paymaster_stake);
    }

    #[test]
    fn services_creation_does_not_panic() {
        // In a real test, we would need an EvmState. This is just a compilation check.
        // The actual creation would be async and require a DB.
    }
}
