use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key error: {0}")]
    Key(String),
}

/// Public key bytes — serializes as hex string for JSON compatibility.
///
/// JSON map keys must be strings, so we serialize as hex instead of byte arrays.
/// This fixes "stakes.json encode: key must be a string" when `BTreeMap<PublicKeyBytes, _>`
/// is serialized to JSON.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl std::fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl std::str::FromStr for PublicKeyBytes {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PublicKeyBytes(hex::decode(s)?))
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s)
            .map(PublicKeyBytes)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKeyBytes;
    fn sign(&self, msg: &[u8]) -> SignatureBytes;
}

pub trait Verifier: Send + Sync {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError>;
}

pub mod ed25519;

pub mod tx;

pub mod keystore;

pub mod remote_signer;

pub mod hsm;
