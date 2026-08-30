use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::DatasetError;

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DatasetError> {
    let mut value = serde_json::to_value(value).map_err(|_| DatasetError::Serialization)?;
    canonicalize(&mut value);
    serde_json::to_vec(&value).map_err(|_| DatasetError::Serialization)
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, DatasetError> {
    canonical_json(value).map(|bytes| sha256_bytes(&bytes))
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Object(object) => {
            let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
            for (_, value) in &mut entries {
                canonicalize(value);
            }
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            object.extend(entries);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
