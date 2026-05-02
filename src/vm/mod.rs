//! IONA Virtual Machine.
//!
//! This module implements a stack‑based VM compatible with EVM semantics.
//! It includes:
//!
//! - Opcode definitions and utilities (`bytecode`)
//! - Execution errors (`errors`)
//! - Gas metering (`gas`)
//! - Full interpreter (`interpreter`)
//! - State abstraction (`state`)
//!
//! # Example
//!
//! ```
//! use iona::vm::{exec, MockVmState, VmState};
//!
//! let code = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];
//! let mut state = MockVmState::new();
//! let caller = [0u8; 32];
//! let result = exec(&mut state, [0u8; 32], &code, &[], &caller, 1_000_000, 0)?;
//! assert!(!result.reverted);
//! ```

pub mod bytecode;
pub mod errors;
pub mod gas;
pub mod interpreter;
pub mod state;

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

pub use bytecode::*;
pub use errors::*;
pub use gas::*;
pub use interpreter::*;
pub use state::{MockVmState, VmState};

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Prelude for convenient importing of common VM items.
pub mod prelude {
    pub use super::{
        exec, GasMeter, Memory, MockVmState, VmError, VmResult, VmState,
    };
    pub use super::bytecode::{
        GAS_BASE, GAS_CALL, GAS_COPY_WORD, GAS_CREATE, GAS_EXTCODE,
        GAS_HIGH, GAS_LOW, GAS_MID, GAS_SHA3, GAS_SLOAD,
        GAS_SSTORE_CLEAR, GAS_SSTORE_RESET, GAS_SSTORE_SET, GAS_VERYLOW,
    };
}
