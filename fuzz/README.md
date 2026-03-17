# Fuzzing Iona with `cargo-fuzz`

This directory contains fuzzing targets for high-risk decoding and execution paths in the Iona protocol.  
Fuzzing helps discover crashes, panics, or assertion failures that could be exploited by malicious input.

## Prerequisites

Install `cargo-fuzz` and the nightly Rust toolchain:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
