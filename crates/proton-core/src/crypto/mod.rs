//! Crypto facade over `proton-crypto` (GopenPGP backend) + `proton-srp`.

pub mod kdf;
pub mod keys;
pub mod message;

pub use keys::{Address, AddressKeys, ApiKey, KeySalt, KeyStore, StoredKey, User};
pub use message::{
    algo_name, decrypt_attachment, decrypt_body, encrypt_attachment, encrypt_for_transport,
    encrypt_self_draft, encrypt_text_with_password, new_session_key, rewrap_attachment_session_key,
    wrap_session_key, wrap_session_key_to_self, wrap_session_key_with_password, SessionKeyMaterial,
    UploadedAttachment, Verdict,
};

/// Obtain Proton's GopenPGP provider.
pub fn provider() -> impl proton_crypto::crypto::PGPProviderSync {
    proton_crypto::new_pgp_provider()
}

/// Verify Proton's signed SRP modulus using the same GopenPGP backend as mail.
pub(crate) struct ModulusVerifier;

impl proton_srp::ModulusSignatureVerifier for ModulusVerifier {
    fn verify_and_extract_modulus(
        &self,
        modulus: &str,
        public_key: &str,
    ) -> std::result::Result<String, proton_srp::ModulusVerifyError> {
        use proton_crypto::crypto::{
            DataEncoding, PGPProviderSync, VerifiedData, Verifier, VerifierSync,
        };
        use proton_srp::ModulusVerifyError as E;
        let p = provider();
        let key = p
            .public_key_import(public_key, DataEncoding::Armor)
            .map_err(|e| E::KeyImport(e.to_string()))?;
        let result = p
            .new_verifier()
            .with_verification_key(&key)
            .verify_cleartext(modulus.as_bytes())
            .map_err(|e| E::CleartextParse(e.to_string()))?;
        result
            .verification_result()
            .map_err(|e| E::SignatureVerification(e.to_string()))?;
        String::from_utf8(result.into_vec()).map_err(|e| E::CleartextParse(e.to_string()))
    }
}
