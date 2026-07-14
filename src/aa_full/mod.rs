//! Full ERC-4337 Account Abstraction.
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
//! services.bundler().add_operation(user_op)?;
//!
//! // Build and submit a bundle
//! let tx_hash = services.bundler().build_and_submit().await?;
//! ```
//!
//! # Feature flags
//! - `aa_full` – enables all account abstraction features (default)
//! - `aa_bundler` – only bundler (for standalone bundler nodes)
//! - `aa_entrypoint` – only EntryPoint precompile (for full nodes)
//! - `aa_paymaster` – paymaster services
//! - `aa_metrics` – enable Prometheus metrics collection

// -----------------------------------------------------------------------------
// Module exports
// -----------------------------------------------------------------------------

pub mod entry_point;
pub mod bundler;
pub mod paymaster;
pub mod simulation;

// Re‑export the most important types for easy access
pub use entry_point::{
    EntryPoint, EntryPointError, EntryPointConfig, HandleOpsResult, ValidationResult,
    ENTRY_POINT_ADDRESS_STR, ENTRY_POINT_ADDRESS,
};
pub use bundler::{Bundler, BundlerConfig, BundlerError, BundlerMetrics};
pub use paymaster::{VerifyingPaymaster, TokenPaymaster, PaymasterError};
pub use simulation::{SimulationError, SimulateResult, simulate_all, SimulationContext};

use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, span, warn, Level};

// Feature‑gated imports
#[cfg(feature = "aa_metrics")]
use lazy_static::lazy_static;
#[cfg(feature = "aa_metrics")]
use prometheus::{register_counter, register_histogram, Counter, Histogram};

// -----------------------------------------------------------------------------
// Metrics (feature‑gated)
// -----------------------------------------------------------------------------

#[cfg(feature = "aa_metrics")]
lazy_static! {
    static ref AA_OPS_RECEIVED: Counter = register_counter!(
        "aa_ops_received_total",
        "Total number of UserOperations received"
    ).unwrap();
    static ref AA_OPS_VALIDATED: Counter = register_counter!(
        "aa_ops_validated_total",
        "Total number of UserOperations that passed validation"
    ).unwrap();
    static ref AA_OPS_FAILED: Counter = register_counter!(
        "aa_ops_failed_total",
        "Total number of UserOperations that failed validation"
    ).unwrap();
    static ref AA_BUNDLES_BUILT: Counter = register_counter!(
        "aa_bundles_built_total",
        "Total number of bundles built"
    ).unwrap();
    static ref AA_BUNDLES_SUBMITTED: Counter = register_counter!(
        "aa_bundles_submitted_total",
        "Total number of bundles submitted to chain"
    ).unwrap();
    static ref AA_BUNDLE_LATENCY: Histogram = register_histogram!(
        "aa_bundle_latency_seconds",
        "Latency from bundle build to submission"
    ).unwrap();
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Main error type for the account abstraction subsystem.
#[derive(Debug, Error)]
pub enum AaError {
    #[error("bundler error: {0}")]
    Bundler(#[from] BundlerError),

    #[error("entry point error: {0}")]
    EntryPoint(#[from] EntryPointError),

    #[error("paymaster error: {0}")]
    Paymaster(#[from] PaymasterError),

    #[error("simulation error: {0}")]
    Simulation(#[from] SimulationError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("mempool error: {0}")]
    Mempool(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("shutdown signal received")]
    Shutdown,
}

pub type AaResult<T> = Result<T, AaError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Central configuration for the entire account abstraction subsystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AaConfig {
    /// EntryPoint precompile configuration.
    pub entrypoint: EntryPointConfig,
    /// Bundler configuration.
    pub bundler: BundlerConfig,
    /// Paymaster configuration (global defaults).
    pub paymaster: PaymasterGlobalConfig,
    /// Simulation defaults.
    pub simulation: SimulationConfig,
    /// Bundler loop interval in milliseconds.
    #[serde(default = "default_loop_interval_ms")]
    pub loop_interval_ms: u64,
    /// Maximum retries for bundle submission.
    #[serde(default = "default_max_submission_retries")]
    pub max_submission_retries: u32,
}

/// EntryPoint configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntryPointConfig {
    /// Whether to enable detailed tracing for each UserOperation.
    #[serde(default)]
    pub trace_ops: bool,
    /// Maximum gas per UserOperation (global cap).
    #[serde(default = "default_max_gas_per_op")]
    pub max_gas_per_op: u64,
}

/// Global paymaster settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaymasterGlobalConfig {
    /// Default verifying paymaster address (if any).
    pub default_verifying_paymaster: Option<String>,
    /// Default token paymaster address.
    pub default_token_paymaster: Option<String>,
    /// Minimum paymaster deposit required (in base units).
    #[serde(default = "default_min_paymaster_deposit")]
    pub min_deposit: u64,
}

/// Simulation configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SimulationConfig {
    /// Maximum number of UserOperations to simulate in one batch.
    #[serde(default = "default_max_simulate_batch")]
    pub max_simulate_batch: usize,
    /// Timeout in milliseconds for each simulation.
    #[serde(default = "default_simulation_timeout_ms")]
    pub timeout_ms: u64,
    /// Whether to enforce paymaster staking checks.
    #[serde(default = "default_true")]
    pub enforce_paymaster_stake: bool,
}

// Default value functions
fn default_loop_interval_ms() -> u64 { 1000 }
fn default_max_submission_retries() -> u32 { 3 }
fn default_max_gas_per_op() -> u64 { 15_000_000 }
fn default_min_paymaster_deposit() -> u64 { 1_000_000_000_000 }
fn default_max_simulate_batch() -> usize { 50 }
fn default_simulation_timeout_ms() -> u64 { 2000 }
fn default_true() -> bool { true }

impl Default for EntryPointConfig {
    fn default() -> Self {
        Self {
            trace_ops: false,
            max_gas_per_op: default_max_gas_per_op(),
        }
    }
}

impl Default for PaymasterGlobalConfig {
    fn default() -> Self {
        Self {
            default_verifying_paymaster: None,
            default_token_paymaster: None,
            min_deposit: default_min_paymaster_deposit(),
        }
    }
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            max_simulate_batch: default_max_simulate_batch(),
            timeout_ms: default_simulation_timeout_ms(),
            enforce_paymaster_stake: default_true(),
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
            loop_interval_ms: default_loop_interval_ms(),
            max_submission_retries: default_max_submission_retries(),
        }
    }
}

impl AaConfig {
    /// Validate the configuration, returning an error if any setting is invalid.
    pub fn validate(&self) -> AaResult<()> {
        if self.entrypoint.max_gas_per_op < 100_000 {
            return Err(AaError::Config(format!(
                "max_gas_per_op too low: {} (minimum 100_000)",
                self.entrypoint.max_gas_per_op
            )));
        }
        if self.bundler.max_ops_per_bundle == 0 {
            return Err(AaError::Config("max_ops_per_bundle must be > 0".into()));
        }
        if self.loop_interval_ms < 100 {
            return Err(AaError::Config(format!(
                "loop_interval_ms too low: {} (minimum 100)",
                self.loop_interval_ms
            )));
        }
        if self.simulation.max_simulate_batch == 0 {
            return Err(AaError::Config("max_simulate_batch must be > 0".into()));
        }
        if self.simulation.timeout_ms < 100 {
            return Err(AaError::Config(format!(
                "simulation timeout too low: {}ms (minimum 100)",
                self.simulation.timeout_ms
            )));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Trait definitions for dependency injection
// -----------------------------------------------------------------------------

/// Provider for the mempool (collects UserOperations from external sources).
#[async_trait::async_trait]
pub trait MempoolProvider: Send + Sync {
    /// Fetch pending UserOperations from the mempool.
    async fn fetch_pending(&self, limit: usize) -> Vec<UserOperation>;

    /// Remove an operation from the mempool after it's been processed.
    async fn remove_processed(&self, op_hash: B256) -> Result<(), AaError>;
}

/// Provider for RPC (submits bundles to the chain).
#[async_trait::async_trait]
pub trait RpcProvider: Send + Sync {
    /// Submit a bundle transaction to the chain.
    async fn submit_bundle(&self, ops: &[UserOperation]) -> Result<B256, AaError>;
}

/// Provider for EVM state access (for simulation).
#[async_trait::async_trait]
pub trait StateProvider: Send + Sync {
    /// Get the current block number.
    async fn block_number(&self) -> Result<u64, AaError>;

    /// Get the current timestamp.
    async fn block_timestamp(&self) -> Result<u64, AaError>;

    /// Get the balance of an address.
    async fn balance(&self, address: Address) -> Result<U256, AaError>;
}

// -----------------------------------------------------------------------------
// Service container
// -----------------------------------------------------------------------------

/// Container for all account abstraction services.
/// This is the main entry point for using ERC-4337 functionality.
pub struct AaServices {
    config: AaConfig,
    bundler: Arc<Bundler>,
    verifying_paymaster: Option<Arc<VerifyingPaymaster>>,
    token_paymaster: Option<Arc<TokenPaymaster>>,
    simulation_context: SimulationContext,
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: Option<mpsc::Receiver<()>>,
    #[cfg(feature = "aa_metrics")]
    metrics: AaMetrics,
}

#[cfg(feature = "aa_metrics")]
struct AaMetrics {
    ops_received: Counter,
    ops_validated: Counter,
    ops_failed: Counter,
    bundles_built: Counter,
    bundles_submitted: Counter,
    bundle_latency: Histogram,
}

#[cfg(not(feature = "aa_metrics"))]
struct AaMetrics;

impl AaServices {
    /// Create a new instance of all AA services.
    pub async fn new(
        config: AaConfig,
        chain_id: u64,
        beneficiary: String,
        evm_state: Arc<dyn StateProvider>,
    ) -> AaResult<Self> {
        // Validate configuration
        config.validate()?;

        info!(chain_id, beneficiary = %beneficiary, "initializing account abstraction services");

        // Create bundler
        let bundler = Arc::new(Bundler::new(beneficiary.clone(), chain_id, config.bundler.clone()));

        // Create paymasters if configured
        let verifying_paymaster = if let Some(addr) = &config.paymaster.default_verifying_paymaster {
            Some(Arc::new(VerifyingPaymaster::new(addr.clone(), evm_state.clone())?))
        } else {
            None
        };

        let token_paymaster = if let Some(addr) = &config.paymaster.default_token_paymaster {
            Some(Arc::new(TokenPaymaster::new(addr.clone(), evm_state.clone())?))
        } else {
            None
        };

        let simulation_context = SimulationContext::new(
            chain_id,
            config.simulation.enforce_paymaster_stake,
        );

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        Ok(Self {
            config,
            bundler,
            verifying_paymaster,
            token_paymaster,
            simulation_context,
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx: Some(shutdown_rx),
            #[cfg(feature = "aa_metrics")]
            metrics: AaMetrics {
                ops_received: AA_OPS_RECEIVED.clone(),
                ops_validated: AA_OPS_VALIDATED.clone(),
                ops_failed: AA_OPS_FAILED.clone(),
                bundles_built: AA_BUNDLES_BUILT.clone(),
                bundles_submitted: AA_BUNDLES_SUBMITTED.clone(),
                bundle_latency: AA_BUNDLE_LATENCY.clone(),
            },
            #[cfg(not(feature = "aa_metrics"))]
            metrics: AaMetrics,
        })
    }

    /// Get a reference to the bundler.
    pub fn bundler(&self) -> &Bundler {
        &self.bundler
    }

    /// Get a reference to the verifying paymaster (if configured).
    pub fn verifying_paymaster(&self) -> Option<&VerifyingPaymaster> {
        self.verifying_paymaster.as_deref()
    }

    /// Get a reference to the token paymaster (if configured).
    pub fn token_paymaster(&self) -> Option<&TokenPaymaster> {
        self.token_paymaster.as_deref()
    }

    /// Get a reference to the simulation context.
    pub fn simulation_context(&self) -> &SimulationContext {
        &self.simulation_context
    }

    /// Get the current configuration.
    pub fn config(&self) -> &AaConfig {
        &self.config
    }

    /// Send a shutdown signal to the service loop.
    pub fn shutdown(&mut self) -> AaResult<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
            info!("shutdown signal sent");
            Ok(())
        } else {
            Err(AaError::Internal("shutdown already triggered".into()))
        }
    }

    /// Create a future that resolves when shutdown is requested.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + Send {
        let mut rx = self.shutdown_rx.clone();
        async move {
            let _ = rx.as_mut().unwrap().recv().await;
        }
    }

    /// Run the bundler's main loop – collects pending ops from mempool, builds and submits bundles.
    /// This is intended for a dedicated bundler thread/task.
    #[instrument(skip_all, fields(interval_ms = %self.config.loop_interval_ms))]
    pub async fn run_bundler_loop<M: MempoolProvider, R: RpcProvider>(
        &self,
        mempool: &M,
        rpc: &R,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> AaResult<()> {
        info!("starting bundler loop");
        let interval = Duration::from_millis(self.config.loop_interval_ms);
        let mut retry_count = 0;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("shutdown received, exiting bundler loop");
                    return Ok(());
                }
                _ = sleep(interval) => {
                    if let Err(e) = self.bundler_iteration(mempool, rpc, &mut retry_count).await {
                        error!(error = %e, "bundler iteration failed");
                        // Exponential backoff on failure
                        let backoff = (100 * 2_u64.pow(retry_count)).min(5000);
                        sleep(Duration::from_millis(backoff)).await;
                        retry_count += 1;
                    } else {
                        retry_count = 0;
                    }
                }
            }
        }
    }

    /// Single iteration of the bundler loop.
    #[instrument(skip_all, fields(attempt = %retry_count))]
    async fn bundler_iteration<M: MempoolProvider, R: RpcProvider>(
        &self,
        mempool: &M,
        rpc: &R,
        retry_count: &mut u32,
    ) -> AaResult<()> {
        let span = span!(Level::INFO, "bundler_iteration");
        let _enter = span.enter();

        // Fetch pending operations
        let ops = mempool.fetch_pending(self.config.bundler.max_ops_per_bundle).await;
        if ops.is_empty() {
            debug!("no pending operations");
            return Ok(());
        }

        #[cfg(feature = "aa_metrics")]
        {
            self.metrics.ops_received.inc_by(ops.len() as u64);
        }

        // Validate and add to bundler
        let mut valid_ops = Vec::new();
        for op in ops {
            match self.bundler.add_operation(op.clone()) {
                Ok(_) => {
                    #[cfg(feature = "aa_metrics")]
                    self.metrics.ops_validated.inc();
                    valid_ops.push(op);
                }
                Err(e) => {
                    #[cfg(feature = "aa_metrics")]
                    self.metrics.ops_failed.inc();
                    warn!(error = %e, "operation validation failed");
                }
            }
        }

        if valid_ops.is_empty() {
            debug!("no valid operations after validation");
            return Ok(());
        }

        // Build bundle
        let start = std::time::Instant::now();
        let bundle = match self.bundler.build_bundle() {
            Some(b) => b,
            None => {
                debug!("no profitable bundle could be built");
                return Ok(());
            }
        };

        #[cfg(feature = "aa_metrics")]
        self.metrics.bundles_built.inc();

        // Submit bundle
        let tx_hash = match self.submit_with_retry(rpc, &bundle, *retry_count).await {
            Ok(hash) => hash,
            Err(e) => {
                error!(error = %e, "bundle submission failed after retries");
                return Err(e);
            }
        };

        #[cfg(feature = "aa_metrics")]
        {
            self.metrics.bundles_submitted.inc();
            self.metrics.bundle_latency.observe(start.elapsed().as_secs_f64());
        }

        info!(tx_hash = %hex::encode(tx_hash.as_bytes()), "bundle submitted");

        // Remove processed ops from mempool
        for op in &bundle {
            let hash = op.hash(ENTRY_POINT_ADDRESS_STR, self.bundler.chain_id);
            let _ = mempool.remove_processed(hash).await;
        }

        Ok(())
    }

    /// Submit a bundle with retries (exponential backoff).
    #[instrument(skip_all)]
    async fn submit_with_retry<R: RpcProvider>(
        &self,
        rpc: &R,
        ops: &[UserOperation],
        base_retry: u32,
    ) -> AaResult<B256> {
        let max_retries = self.config.max_submission_retries + base_retry;
        let mut retry_count = 0;

        loop {
            retry_count += 1;
            match rpc.submit_bundle(ops).await {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    if retry_count >= max_retries {
                        return Err(e);
                    }
                    let backoff = (100 * 2_u64.pow(retry_count)).min(5000);
                    warn!(retry = retry_count, backoff_ms = backoff, error = %e, "bundle submission failed, retrying");
                    sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }
}

/// Convenience function to initialize the entire AA subsystem with default config.
pub async fn init_account_abstraction(
    config: AaConfig,
    chain_id: u64,
    beneficiary: String,
    evm_state: Arc<dyn StateProvider>,
) -> AaResult<AaServices> {
    AaServices::new(config, chain_id, beneficiary, evm_state).await
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct MockStateProvider;
    #[async_trait::async_trait]
    impl StateProvider for MockStateProvider {
        async fn block_number(&self) -> Result<u64, AaError> { Ok(100) }
        async fn block_timestamp(&self) -> Result<u64, AaError> { Ok(1000) }
        async fn balance(&self, _address: Address) -> Result<U256, AaError> { Ok(U256::from(1_000_000)) }
    }

    #[test]
    fn config_validation_passes() {
        let config = AaConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validation_fails_low_loop_interval() {
        let mut config = AaConfig::default();
        config.loop_interval_ms = 50;
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_fails_low_gas_limit() {
        let mut config = AaConfig::default();
        config.entrypoint.max_gas_per_op = 50_000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_fails_zero_max_ops() {
        let mut config = AaConfig::default();
        config.bundler.max_ops_per_bundle = 0;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn services_creation_succeeds() {
        let config = AaConfig::default();
        let evm_state = Arc::new(MockStateProvider);
        let services = AaServices::new(config, 1, "beneficiary".into(), evm_state).await;
        assert!(services.is_ok());
    }

    #[tokio::test]
    async fn shutdown_signal_works() {
        let config = AaConfig::default();
        let evm_state = Arc::new(MockStateProvider);
        let mut services = AaServices::new(config, 1, "beneficiary".into(), evm_state).await.unwrap();
        let signal = services.shutdown_signal();
        services.shutdown().unwrap();
        // Signal should resolve immediately
        tokio::time::timeout(Duration::from_millis(100), signal).await.unwrap();
    }

    #[tokio::test]
    async fn bundler_loop_shutdown() {
        let config = AaConfig::default();
        let evm_state = Arc::new(MockStateProvider);
        let services = AaServices::new(config, 1, "beneficiary".into(), evm_state).await.unwrap();

        struct MockMempool;
        #[async_trait::async_trait]
        impl MempoolProvider for MockMempool {
            async fn fetch_pending(&self, _limit: usize) -> Vec<UserOperation> {
                Vec::new()
            }
            async fn remove_processed(&self, _op_hash: B256) -> Result<(), AaError> {
                Ok(())
            }
        }

        struct MockRpc;
        #[async_trait::async_trait]
        impl RpcProvider for MockRpc {
            async fn submit_bundle(&self, _ops: &[UserOperation]) -> Result<B256, AaError> {
                Ok(B256::ZERO)
            }
        }

        let mempool = MockMempool;
        let rpc = MockRpc;
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let handle = tokio::spawn(async move {
            services.run_bundler_loop(&mempool, &rpc, shutdown_rx).await
        });

        // Wait a tiny bit, then shutdown
        sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(()).await.unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}
