# Client signing example (Rust)

```rust
use ed25519_dalek::{SigningKey, Signer};
use base64::Engine;

fn main() {
    let seed = [1u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes().to_vec();

    let chain_id = 1u64;
    let nonce = 0u64;
    let max_fee_per_gas = 5u64;
    let max_priority_fee_per_gas = 2u64;
    let gas_limit = 50_000u64;
    let payload = "set hello world";

    let sign_bytes = serde_json::to_vec(&(
        "iona-tx-v1",
        chain_id,
        &pk,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        payload,
    )).unwrap();

    let sig = sk.sign(&sign_bytes).to_bytes();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);

    println!("pubkey_hex={}", hex::encode(pk));
    println!("signature_b64={sig_b64}");
}
```
