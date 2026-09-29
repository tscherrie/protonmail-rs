//! Headless encrypted credential storage. The 32-byte key should be supplied
//! through a service manager credential, separately from the persistent state.
use super::SecretStore;
use crate::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(crate) fn validate_profile(profile: &str) -> Result<()> {
    if profile.is_empty()
        || profile.len() > 64
        || !profile
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(Error::Session(
            "profile must contain 1-64 letters, digits, hyphens or underscores".into(),
        ));
    }
    Ok(())
}

pub(crate) struct SealedStore {
    dir: PathBuf,
    key: Zeroizing<Vec<u8>>,
    profile: String,
}

impl SealedStore {
    pub(crate) fn new(dir: &Path, key_file: &Path, profile: &str) -> Result<Self> {
        validate_profile(profile)?;
        let key = Zeroizing::new(std::fs::read(key_file)?);
        if key.len() != 32 {
            return Err(Error::Session(
                "secret store key must be exactly 32 bytes".into(),
            ));
        }
        let dir = dir.join(profile);
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir,
            key,
            profile: profile.into(),
        })
    }
    fn file(&self, key: &str) -> Result<PathBuf> {
        if !matches!(key, "access_token" | "refresh_token" | "skp") {
            return Err(Error::Session("unsupported secret name".into()));
        }
        Ok(self.dir.join(format!("{key}.sealed")))
    }
    fn aad(&self, key: &str) -> String {
        format!("proton-mcp:v1:{}:{key}", self.profile)
    }
}

impl SecretStore for SealedStore {
    fn set(&self, key: &str, value: &str) -> Result<()> {
        let file = self.file(key)?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| Error::Session("invalid store key".into()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value.as_bytes(),
                    aad: self.aad(key).as_bytes(),
                },
            )
            .map_err(|_| Error::Session("secret encryption failed".into()))?;
        let tmp = self.dir.join(format!(".tmp-{}", rand::random::<u64>()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut out = options.open(&tmp)?;
        out.write_all(&nonce)?;
        out.write_all(&ciphertext)?;
        out.sync_all()?;
        std::fs::rename(&tmp, &file)?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<String>> {
        let bytes = match std::fs::read(self.file(key)?) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() < 28 {
            return Err(Error::Session("invalid encrypted secret".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| Error::Session("invalid store key".into()))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&bytes[..12]),
                    Payload {
                        msg: &bytes[12..],
                        aad: self.aad(key).as_bytes(),
                    },
                )
                .map_err(|_| Error::Session("secret authentication failed".into()))?,
        );
        let value = std::str::from_utf8(&plain)
            .map_err(|_| Error::Session("invalid secret encoding".into()))?;
        Ok(Some(value.to_string()))
    }
    fn delete(&self, key: &str) -> Result<()> {
        match std::fs::remove_file(self.file(key)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_store_survives_restart_and_rejects_tampering() {
        let dir = std::env::temp_dir().join(format!("sealed-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("key");
        std::fs::write(&key, [42u8; 32]).unwrap();
        let store = SealedStore::new(&dir, &key, "test").unwrap();
        store.set("refresh_token", "secret-test-value").unwrap();
        let path = store.file("refresh_token").unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(17).any(|w| w == b"secret-test-value"));
        let restarted = SealedStore::new(&dir, &key, "test").unwrap();
        assert_eq!(
            restarted.get("refresh_token").unwrap().as_deref(),
            Some("secret-test-value")
        );
        bytes[20] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(restarted.get("refresh_token").is_err());
        assert!(SealedStore::new(&dir, &key, "../escape").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
