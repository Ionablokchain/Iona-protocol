//! Economic parameters of the IONA protocol.
//!
//! [`EconomicsParams`] groups every tunable that affects inflation, slashing,
//! unbonding, and treasury allocation. All ratio fields are expressed in
//! **basis points** (1 bp = 0.01 %, 10 000 bp = 100 %).
//!
//! # Invariants
//!
//! A parameter set that passes [`EconomicsParams::validate`] guarantees:
//!
//! - every `_bps` field is `≤ 10_000`,
//! - `slash_double_sign_bps + slash_downtime_bps ≤ 10_000` (a validator
//!   can never be slashed for more than their entire bond in one event),
//! - `min_stake ≥ 1`,
//! - `1 ≤ unbonding_epochs ≤ MAX_UNBONDING_EPOCHS`.
//!
//! # Numeric precision
//!
//! The `f64`-returning helpers ([`inflation_rate`], [`validator_reward_share`])
//! are intended for display and telemetry. Consensus-critical code should use
//! the integer helpers ([`inflation_bps`], [`validator_reward_bps`],
//! [`slash_double_sign_amount`], [`slash_downtime_amount`]) which are exact.
//!
//! [`inflation_rate`]: EconomicsParams::inflation_rate
//! [`validator_reward_share`]: EconomicsParams::validator_reward_share

use serde::{Deserialize, Serialize};

// ── Constants ─────────────────────────────────────────────────────────────

/// Basis-points denominator: 10 000 bp = 100 %.
pub const MAX_BPS: u64 = 10_000;

/// Smallest permitted `min_stake`.
pub const MIN_STAKE: u128 = 1;

/// Upper bound on the unbonding period (defensive; ~2 years at 6 s blocks).
pub const MAX_UNBONDING_EPOCHS: u64 = 20_000;

// ── Parameter struct ──────────────────────────────────────────────────────

/// Economic parameters of the IONA protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicsParams {
    /// Annual inflation rate in basis points. `500` = 5 %.
    #[serde(default = "default_base_inflation_bps")]
    pub base_inflation_bps: u64,

    /// Minimum stake required to be a validator, in base units.
    #[serde(default = "default_min_stake")]
    pub min_stake: u128,

    /// Slashing penalty for double-signing, in bps of bonded stake.
    /// `5_000` = 50 %.
    #[serde(default = "default_slash_double_sign_bps")]
    pub slash_double_sign_bps: u64,

    /// Slashing penalty for downtime, in bps of bonded stake.
    /// `100` = 1 %.
    #[serde(default = "default_slash_downtime_bps")]
    pub slash_downtime_bps: u64,

    /// Number of epochs a validator waits after unbonding before funds are
    /// released.
    #[serde(default = "default_unbonding_epochs")]
    pub unbonding_epochs: u64,

    /// Fraction of inflation routed to the treasury, in bps. The remainder
    /// goes to validators and delegators.
    #[serde(default = "default_treasury_bps")]
    pub treasury_bps: u64,
}

impl Default for EconomicsParams {
    fn default() -> Self {
        Self {
            base_inflation_bps: default_base_inflation_bps(),
            min_stake: default_min_stake(),
            slash_double_sign_bps: default_slash_double_sign_bps(),
            slash_downtime_bps: default_slash_downtime_bps(),
            unbonding_epochs: default_unbonding_epochs(),
            treasury_bps: default_treasury_bps(),
        }
    }
}

// ── Serde defaults ────────────────────────────────────────────────────────

fn default_base_inflation_bps() -> u64 {
    500 // 5 %
}
fn default_min_stake() -> u128 {
    10_000_000_000 // 10 billion units
}
fn default_slash_double_sign_bps() -> u64 {
    5_000 // 50 %
}
fn default_slash_downtime_bps() -> u64 {
    100 // 1 %
}
fn default_unbonding_epochs() -> u64 {
    14
}
fn default_treasury_bps() -> u64 {
    500 // 5 %
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Why an [`EconomicsParams`] set is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EconParamsError {
    #[error("base_inflation_bps must be <= {MAX_BPS} (got {got})")]
    InflationTooHigh { got: u64 },
    #[error("slash_double_sign_bps must be <= {MAX_BPS} (got {got})")]
    DoubleSignSlashTooHigh { got: u64 },
    #[error("slash_downtime_bps must be <= {MAX_BPS} (got {got})")]
    DowntimeSlashTooHigh { got: u64 },
    #[error(
        "slash_double_sign_bps + slash_downtime_bps must be <= {MAX_BPS} \
         (got {double_sign} + {downtime} = {sum})"
    )]
    TotalSlashExceedsBond {
        double_sign: u64,
        downtime: u64,
        sum: u64,
    },
    #[error("treasury_bps must be <= {MAX_BPS} (got {got})")]
    TreasuryTooHigh { got: u64 },
    #[error("min_stake must be >= {MIN_STAKE} (got {got})")]
    MinStakeTooLow { got: u128 },
    #[error("unbonding_epochs must be > 0")]
    UnbondingZero,
    #[error("unbonding_epochs must be <= {MAX_UNBONDING_EPOCHS} (got {got})")]
    UnbondingTooLong { got: u64 },
}

// ── Implementation ────────────────────────────────────────────────────────

impl EconomicsParams {
    /// Validate the parameter set.
    pub fn validate(&self) -> Result<(), EconParamsError> {
        if self.base_inflation_bps > MAX_BPS {
            return Err(EconParamsError::InflationTooHigh {
                got: self.base_inflation_bps,
            });
        }
        if self.slash_double_sign_bps > MAX_BPS {
            return Err(EconParamsError::DoubleSignSlashTooHigh {
                got: self.slash_double_sign_bps,
            });
        }
        if self.slash_downtime_bps > MAX_BPS {
            return Err(EconParamsError::DowntimeSlashTooHigh {
                got: self.slash_downtime_bps,
            });
        }

        let total_slash = self
            .slash_double_sign_bps
            .saturating_add(self.slash_downtime_bps);
        if total_slash > MAX_BPS {
            return Err(EconParamsError::TotalSlashExceedsBond {
                double_sign: self.slash_double_sign_bps,
                downtime: self.slash_downtime_bps,
                sum: total_slash,
            });
        }

        if self.treasury_bps > MAX_BPS {
            return Err(EconParamsError::TreasuryTooHigh {
                got: self.treasury_bps,
            });
        }
        if self.min_stake < MIN_STAKE {
            return Err(EconParamsError::MinStakeTooLow {
                got: self.min_stake,
            });
        }
        if self.unbonding_epochs == 0 {
            return Err(EconParamsError::UnbondingZero);
        }
        if self.unbonding_epochs > MAX_UNBONDING_EPOCHS {
            return Err(EconParamsError::UnbondingTooLong {
                got: self.unbonding_epochs,
            });
        }
        Ok(())
    }

    /// Construct a validated parameter set.
    ///
    /// Prefer this over [`Default::default`] when the caller can surface an
    /// error, so invalid defaults cannot slip through.
    pub fn try_new(params: Self) -> Result<Self, EconParamsError> {
        params.validate()?;
        Ok(params)
    }

    // ── Rate accessors ──────────────────────────────────────────────────

    /// Annual inflation, in basis points. Exact.
    #[must_use]
    pub fn inflation_bps(&self) -> u64 {
        self.base_inflation_bps
    }

    /// Annual inflation as an `f64` fraction (e.g. `0.05` for 5 %).
    ///
    /// **Display only** — see module docs.
    #[must_use]
    pub fn inflation_rate(&self) -> f64 {
        self.base_inflation_bps as f64 / MAX_BPS as f64
    }

    /// Fraction of inflation routed to validators and delegators, in bps.
    ///
    /// Exact: `10_000 - treasury_bps`. Callers that need an `f64` should use
    /// [`validator_reward_share`](Self::validator_reward_share).
    #[must_use]
    pub fn validator_reward_bps(&self) -> u64 {
        MAX_BPS.saturating_sub(self.treasury_bps)
    }

    /// Fraction of inflation routed to validators and delegators, as an
    /// `f64` in `[0, 1]`.
    ///
    /// **Display only** — see module docs. The result is clamped so a
    /// mis-configured `treasury_bps > MAX_BPS` cannot produce a negative
    /// value; use [`validate`](Self::validate) to reject such configs.
    #[must_use]
    pub fn validator_reward_share(&self) -> f64 {
        (self.validator_reward_bps() as f64 / MAX_BPS as f64).clamp(0.0, 1.0)
    }

    // ── Slash amount calculators ────────────────────────────────────────

    /// Slash amount for a double-sign, in the same units as `stake`.
    ///
    /// `stake * slash_double_sign_bps / MAX_BPS` computed **exactly** via a
    /// split-multiply-divide so no intermediate product can overflow even
    /// for `stake == u128::MAX`.
    #[must_use]
    pub fn slash_double_sign_amount(&self, stake: u128) -> u128 {
        mul_div_u128(stake, self.slash_double_sign_bps, MAX_BPS)
    }

    /// Slash amount for downtime, in the same units as `stake`.
    ///
    /// See [`slash_double_sign_amount`](Self::slash_double_sign_amount) for
    /// the overflow contract.
    #[must_use]
    pub fn slash_downtime_amount(&self, stake: u128) -> u128 {
        mul_div_u128(stake, self.slash_downtime_bps, MAX_BPS)
    }
}

// ── Exact `a * b / c` for u128 ────────────────────────────────────────────

/// Compute `a * b / c` exactly for `u128`, without any intermediate overflow.
///
/// Splits `a` into quotient and remainder modulo `c`, multiplies each part
/// by `b`, and sums the pieces. Requires `b ≤ c` (which holds for every
/// basis-points field, since `MAX_BPS == 10_000`).
///
/// The result is the mathematical floor of `a * b / c`; no precision is
/// lost.
#[inline]
fn mul_div_u128(a: u128, b: u64, c: u64) -> u128 {
    debug_assert!(c != 0, "mul_div_u128: division by zero");
    debug_assert!(b <= c, "mul_div_u128: multiplier must not exceed divisor");

    let c = c as u128;
    let b = b as u128;
    let hi = a / c;
    let lo = a % c;
    // hi * b <= (a / c) * c <= a, so this cannot overflow.
    // lo * b < c * c <= 10^8, so this cannot overflow either.
    hi * b + (lo * b) / c
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Defaults & construction ─────────────────────────────────────────

    #[test]
    fn defaults_are_valid() {
        assert!(EconomicsParams::default().validate().is_ok());
    }

    #[test]
    fn try_new_accepts_valid_and_rejects_invalid() {
        assert!(EconomicsParams::try_new(EconomicsParams::default()).is_ok());
        let bad = EconomicsParams {
            base_inflation_bps: MAX_BPS + 1,
            ..Default::default()
        };
        assert!(matches!(
            EconomicsParams::try_new(bad),
            Err(EconParamsError::InflationTooHigh { .. })
        ));
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn validation_rejects_each_field_individually() {
        let cases = [
            (
                EconomicsParams { base_inflation_bps: MAX_BPS + 1, ..Default::default() },
                "inflation",
            ),
            (
                EconomicsParams { slash_double_sign_bps: MAX_BPS + 1, ..Default::default() },
                "double_sign",
            ),
            (
                EconomicsParams { slash_downtime_bps: MAX_BPS + 1, ..Default::default() },
                "downtime",
            ),
            (
                EconomicsParams { treasury_bps: MAX_BPS + 1, ..Default::default() },
                "treasury",
            ),
            (
                EconomicsParams { min_stake: 0, ..Default::default() },
                "min_stake",
            ),
            (
                EconomicsParams { unbonding_epochs: 0, ..Default::default() },
                "unbonding_zero",
            ),
            (
                EconomicsParams { unbonding_epochs: MAX_UNBONDING_EPOCHS + 1, ..Default::default() },
                "unbonding_long",
            ),
        ];
        for (p, label) in cases {
            assert!(p.validate().is_err(), "case {label} should fail");
        }
    }

    #[test]
    fn validation_rejects_total_slash_above_100_percent() {
        let p = EconomicsParams {
            slash_double_sign_bps: 6_000,
            slash_downtime_bps: 5_000,
            ..Default::default()
        };
        assert!(matches!(
            p.validate(),
            Err(EconParamsError::TotalSlashExceedsBond { .. })
        ));
    }

    #[test]
    fn validation_accepts_boundary_values() {
        let p = EconomicsParams {
            base_inflation_bps: MAX_BPS,
            slash_double_sign_bps: MAX_BPS,
            slash_downtime_bps: 0,
            treasury_bps: MAX_BPS,
            min_stake: MIN_STAKE,
            unbonding_epochs: MAX_UNBONDING_EPOCHS,
        };
        assert!(p.validate().is_ok());
    }

    // ── Slash amounts ───────────────────────────────────────────────────

    #[test]
    fn slash_amounts_are_exact_for_small_stakes() {
        let params = EconomicsParams::default();
        let stake = 1_000_000u128;
        assert_eq!(params.slash_double_sign_amount(stake), 500_000);
        assert_eq!(params.slash_downtime_amount(stake), 10_000);
    }

    #[test]
    fn slash_amount_does_not_overflow_at_u128_max() {
        // Regression: `stake * bps as u128` overflows for large stakes.
        let params = EconomicsParams {
            slash_double_sign_bps: MAX_BPS, // 100 %
            ..Default::default()
        };
        let stake = u128::MAX;
        let amount = params.slash_double_sign_amount(stake);
        // 100 % of `stake` must equal `stake`.
        assert_eq!(amount, stake);
    }

    #[test]
    fn slash_amount_matches_reference_for_random_values() {
        // For any value the split-multiply-divide produces the same result
        // as `u128::max`-safe arithmetic would, if it existed.
        let bps = [1u64, 100, 500, 5_000, 9_999, MAX_BPS];
        for b in bps {
            let p = EconomicsParams {
                slash_double_sign_bps: b,
                ..Default::default()
            };
            for stake in [0u128, 1, 999, 1_000, 1_000_000, (1u128 << 100), u128::MAX] {
                let got = p.slash_double_sign_amount(stake);
                // Reference: `(stake as u256) * b / 10_000`, computed via
                // Rust's `u128::checked_mul` where possible, and otherwise
                // via the split formula.
                let want = match stake.checked_mul(b as u128) {
                    Some(prod) => prod / MAX_BPS as u128,
                    None => {
                        let hi = stake / MAX_BPS as u128;
                        let lo = stake % MAX_BPS as u128;
                        hi * b as u128 + lo * b as u128 / MAX_BPS as u128
                    }
                };
                assert_eq!(got, want, "bps={b} stake={stake}");
            }
        }
    }

    // ── Rates ───────────────────────────────────────────────────────────

    #[test]
    fn inflation_rate_matches_bps() {
        let p = EconomicsParams::default();
        assert!((p.inflation_rate() - 0.05).abs() < 1e-12);
        assert_eq!(p.inflation_bps(), 500);
    }

    #[test]
    fn validator_reward_share_is_exact_bps() {
        let p = EconomicsParams::default();
        assert_eq!(p.validator_reward_bps(), 9_500);
        assert!((p.validator_reward_share() - 0.95).abs() < 1e-12);
    }

    #[test]
    fn validator_reward_share_clamps_when_treasury_over_100() {
        // `validate` rejects this config, but the helper must still be
        // numerically sane.
        let p = EconomicsParams {
            treasury_bps: MAX_BPS + 1,
            ..Default::default()
        };
        let share = p.validator_reward_share();
        assert!((0.0..=1.0).contains(&share));
    }

    // ── Serde roundtrip ─────────────────────────────────────────────────

    #[test]
    fn serde_roundtrip_preserves_values() {
        let p = EconomicsParams {
            base_inflation_bps: 750,
            min_stake: 42_000_000,
            slash_double_sign_bps: 2_500,
            slash_downtime_bps: 250,
            unbonding_epochs: 21,
            treasury_bps: 1_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: EconomicsParams = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn serde_defaults_fill_missing_fields() {
        let json = r#"{}"#;
        let p: EconomicsParams = serde_json::from_str(json).unwrap();
        assert_eq!(p, EconomicsParams::default());
    }
}
