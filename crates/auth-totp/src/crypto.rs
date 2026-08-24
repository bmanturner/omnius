use std::sync::Arc;

use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use hmac::{Hmac, Mac as _};
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::TotpStoreError;

pub(crate) const SEED_BYTES: usize = 20;
pub(crate) const SEED_CIPHERTEXT_BYTES: usize = SEED_BYTES + 16;
pub(crate) const SEED_ENCRYPTION_VERSION: i16 = 1;

const KEY_BYTES: usize = 32;
const SEED_KEY_DOMAIN: &[u8] = b"rsk-auth-totp/seed-encryption-key/v1";
const RECOVERY_PEPPER_DOMAIN: &[u8] = b"rsk-auth-totp/recovery-code-pepper/v1";
const SEED_AAD_DOMAIN: &[u8; 22] = b"rsk-auth-totp/seed/v1\0";
const SEED_AAD_BYTES: usize = SEED_AAD_DOMAIN.len() + 16;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct KeyMaterial {
    pub(crate) seed_cipher: SeedCipher,
    pub(crate) recovery_pepper: Arc<Zeroizing<[u8; KEY_BYTES]>>,
}

impl KeyMaterial {
    pub(crate) fn derive(master: &[u8; KEY_BYTES]) -> Result<Self, TotpStoreError> {
        let seed_key = derive_subkey(master, SEED_KEY_DOMAIN)?;
        let recovery_pepper = derive_subkey(master, RECOVERY_PEPPER_DOMAIN)?;
        Ok(Self {
            seed_cipher: SeedCipher::new(seed_key),
            recovery_pepper: Arc::new(recovery_pepper),
        })
    }
}

#[derive(Clone)]
pub(crate) struct SeedCipher {
    key: Arc<Zeroizing<[u8; KEY_BYTES]>>,
}

impl SeedCipher {
    fn new(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self { key: Arc::new(key) }
    }

    pub(crate) fn encrypt(
        &self,
        user_id: Uuid,
        seed: &[u8; SEED_BYTES],
    ) -> Result<EncryptedSeed, TotpStoreError> {
        let key = RandomizedNonceKey::new(&AES_256_GCM, self.key.as_ref().as_slice())
            .map_err(|_| TotpStoreError::Cryptography)?;
        let aad = seed_aad(user_id);
        let mut buffer = Zeroizing::new(Vec::with_capacity(SEED_CIPHERTEXT_BYTES));
        buffer.extend_from_slice(seed);
        let nonce = key
            .seal_in_place_append_tag(Aad::from(aad), &mut *buffer)
            .map_err(|_| TotpStoreError::Cryptography)?;
        if buffer.len() != SEED_CIPHERTEXT_BYTES {
            return Err(TotpStoreError::Cryptography);
        }
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(nonce.as_ref());
        Ok(EncryptedSeed {
            ciphertext: std::mem::take(&mut *buffer),
            nonce: nonce_bytes,
        })
    }

    pub(crate) fn decrypt(
        &self,
        user_id: Uuid,
        nonce: [u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TotpStoreError> {
        if ciphertext.len() != SEED_CIPHERTEXT_BYTES {
            return Err(TotpStoreError::CorruptData);
        }
        let key = RandomizedNonceKey::new(&AES_256_GCM, self.key.as_ref().as_slice())
            .map_err(|_| TotpStoreError::Cryptography)?;
        let aad = seed_aad(user_id);
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        let plaintext_len = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut buffer,
            )
            .map_err(|_| TotpStoreError::CorruptData)?
            .len();
        if plaintext_len != SEED_BYTES {
            return Err(TotpStoreError::CorruptData);
        }
        buffer.truncate(plaintext_len);
        Ok(buffer)
    }
}

pub(crate) struct EncryptedSeed {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) nonce: [u8; NONCE_LEN],
}

pub(crate) fn generate_seed() -> Result<Zeroizing<[u8; SEED_BYTES]>, TotpStoreError> {
    let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
    OsRng
        .try_fill_bytes(&mut *seed)
        .map_err(|_| TotpStoreError::EntropyUnavailable)?;
    Ok(seed)
}

fn derive_subkey(
    master: &[u8; KEY_BYTES],
    domain: &[u8],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, TotpStoreError> {
    let mut hmac = HmacSha256::new_from_slice(master).map_err(|_| TotpStoreError::Cryptography)?;
    hmac.update(domain);
    let mut output = hmac.finalize().into_bytes();
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    key.copy_from_slice(&output);
    output.as_mut_slice().zeroize();
    Ok(key)
}

fn seed_aad(user_id: Uuid) -> [u8; SEED_AAD_BYTES] {
    let mut aad = [0_u8; SEED_AAD_BYTES];
    aad[..SEED_AAD_DOMAIN.len()].copy_from_slice(SEED_AAD_DOMAIN);
    aad[SEED_AAD_DOMAIN.len()..].copy_from_slice(user_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_USER: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
    const SECOND_USER: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);

    #[test]
    fn subkey_derivation_is_deterministic_and_domain_separated() -> Result<(), TotpStoreError> {
        let master = [17_u8; KEY_BYTES];
        let first_seed = derive_subkey(&master, SEED_KEY_DOMAIN)?;
        let second_seed = derive_subkey(&master, SEED_KEY_DOMAIN)?;
        let recovery = derive_subkey(&master, RECOVERY_PEPPER_DOMAIN)?;

        assert_eq!(*first_seed, *second_seed);
        assert_ne!(*first_seed, *recovery);
        Ok(())
    }

    #[test]
    fn seed_cipher_round_trips_and_binds_ciphertext_to_user() -> Result<(), TotpStoreError> {
        let cipher = SeedCipher::new(derive_subkey(&[23_u8; KEY_BYTES], SEED_KEY_DOMAIN)?);
        let seed = [41_u8; SEED_BYTES];
        let encrypted = cipher.encrypt(FIRST_USER, &seed)?;

        assert_ne!(encrypted.ciphertext.as_slice(), seed.as_slice());
        assert_eq!(
            cipher
                .decrypt(FIRST_USER, encrypted.nonce, &encrypted.ciphertext)?
                .as_slice(),
            seed
        );
        assert_eq!(
            cipher.decrypt(SECOND_USER, encrypted.nonce, &encrypted.ciphertext),
            Err(TotpStoreError::CorruptData)
        );
        Ok(())
    }
}
