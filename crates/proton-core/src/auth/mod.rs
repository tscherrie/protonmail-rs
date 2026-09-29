//! SRP login, 2FA, refresh, and logout.

pub mod types;

use crate::error::{Error, Result};
use crate::session::Tokens;
use crate::transport::{Doer, HttpClient, Request};
use proton_srp::{SRPAuth, SRPProofB64, SrpHashVersion};
use secrecy::{ExposeSecret, SecretString};
use types::{AuthInfo, AuthResponse};

/// Result of a successful login.
pub struct LoginResult {
    /// Session tokens (UID, access, refresh) for the authenticated session.
    pub tokens: Tokens,
    /// Password mode: `1` for single-password, `2` for separate mailbox password.
    pub password_mode: u8,
}

/// Perform the full SRP login (+ 2FA if required).
pub async fn login(
    http: &HttpClient,
    username: &str,
    password: &SecretString,
    totp: Option<&str>,
) -> Result<LoginResult> {
    tracing::info!(target: "proton_core::auth", username, "login: starting SRP flow");

    // 1. Fetch the challenge without a session, as in go-proton-api's manager login.
    // Omit any existing session credentials even when this client is reused.
    tracing::debug!(target: "proton_core::auth", "login step 1/3: fetching SRP challenge (POST /auth/v4/info)");
    let info: AuthInfo = http
        .decode(
            Request::post("/auth/v4/info")
                .json(serde_json::json!({ "Username": username }))
                .unauthenticated()
                .no_refresh(),
        )
        .await?;
    tracing::debug!(target: "proton_core::auth", srp_version = info.version, salt_len = info.salt.len(), modulus_len = info.modulus.len(), "login: received modulus, salt, server ephemeral");

    // 2. Compute SRP proofs after verifying the signed modulus.
    let version = SrpHashVersion::try_from(info.version)
        .map_err(|e| Error::Srp(format!("unsupported SRP version {}: {e}", info.version)))?;
    tracing::debug!(target: "proton_core::auth", "login step 2/3: verifying signed modulus + generating client proof (proton-srp)");
    let verifier = crate::crypto::ModulusVerifier;
    let srp = SRPAuth::new(
        &verifier,
        Some(username),
        password.expose_secret(),
        version,
        &info.salt,
        &info.modulus,
        &info.server_ephemeral,
    )
    .map_err(|e| Error::Srp(format!("SRP setup failed: {e}")))?;
    let proof = srp
        .generate_proofs()
        .map_err(|e| Error::Srp(format!("SRP proof failed: {e}")))?;
    tracing::debug!(target: "proton_core::auth", "login: client proof + ephemeral generated; modulus signature verified");
    let b64: SRPProofB64 = proof.into();

    // 3. Submit the proof without pre-authentication session credentials.
    tracing::debug!(target: "proton_core::auth", "login step 3/3: submitting client proof (POST /auth/v4)");
    let resp: AuthResponse = http
        .decode(
            Request::post("/auth/v4")
                .json(serde_json::json!({
                    "Username": username,
                    "ClientProof": b64.client_proof,
                    "ClientEphemeral": b64.client_ephemeral,
                    "SRPSession": info.srp_session,
                }))
                .unauthenticated()
                .no_refresh(),
        )
        .await?;

    // Verify the server proof before accepting any returned tokens (MITM guard).
    if !b64.compare_server_proof(&resp.server_proof) {
        tracing::error!(target: "proton_core::auth", "login: SERVER PROOF MISMATCH — aborting (possible MITM)");
        return Err(Error::Srp("server proof verification failed".into()));
    }
    tracing::info!(target: "proton_core::auth", uid = %resp.uid, password_mode = resp.password_mode, two_fa = resp.two_fa.enabled, "login: server proof verified; authenticated");

    // Promote to the authenticated session.
    http.set_tokens(
        resp.uid.clone(),
        SecretString::from(resp.access_token.clone()),
        SecretString::from(resp.refresh_token.clone()),
    )
    .await;

    // 2FA if required. TOTP is bit 0; FIDO2/WebAuthn is bit 1.
    if resp.two_fa.enabled & 1 == 0 && resp.two_fa.enabled & 2 != 0 {
        return Err(Error::Other(
            "this account requires a security key (FIDO2/WebAuthn) for 2FA, which is not yet \
             supported — enable a TOTP authenticator app, or use an app/bridge password"
                .into(),
        ));
    }
    if resp.two_fa.enabled & 1 != 0 {
        tracing::debug!(target: "proton_core::auth", "login: 2FA required — submitting TOTP (POST /auth/v4/2fa)");
        let code = totp.ok_or_else(|| {
            Error::Other("account requires 2FA but no TOTP code was provided".into())
        })?;
        let _: serde_json::Value = http
            .decode(
                Request::post("/auth/v4/2fa")
                    .json(serde_json::json!({ "TwoFactorCode": code }))
                    .no_refresh(),
            )
            .await?;
        tracing::debug!(target: "proton_core::auth", "login: 2FA accepted");
    }
    tracing::info!(target: "proton_core::auth", "login: complete");

    Ok(LoginResult {
        tokens: Tokens {
            uid: resp.uid,
            access: SecretString::from(resp.access_token),
            refresh: SecretString::from(resp.refresh_token),
        },
        password_mode: resp.password_mode,
    })
}

/// Revoke the current session server-side.
pub async fn logout(http: &HttpClient) -> Result<()> {
    let _: serde_json::Value = http.decode(Request::delete("/core/v4/auth")).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proton_srp::{SRPVerifierB64, ServerClientProof, ServerClientVerifier, ServerInteraction};
    use std::sync::Mutex;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Public, signed fixture from proton-srp 0.8.2's tests/srp.rs (MIT).
    // The production verifier is used throughout: no signature or proof bypasses.
    const SIGNED_MODULUS: &str = include_str!("fixtures/srp-modulus.asc");
    const TEST_USERNAME: &str = "local-fixture-user";
    const TEST_PASSWORD: &str = "local-fixture-password";

    async fn mock_srp_login(server: &MockServer, two_fa: u32, corrupt_server_proof: bool) {
        let verifier = crate::crypto::ModulusVerifier;
        let client_verifier: SRPVerifierB64 =
            SRPAuth::generate_verifier(&verifier, TEST_PASSWORD, None, SIGNED_MODULUS)
                .unwrap()
                .into();
        let server_verifier = ServerClientVerifier::try_from(&client_verifier).unwrap();
        let mut srp_server = ServerInteraction::new_with_modulus_extractor(
            &verifier,
            SIGNED_MODULUS,
            &server_verifier,
        )
        .unwrap();
        let challenge = srp_server.generate_challenge().encode_b64();
        Mock::given(method("POST"))
            .and(path("/auth/v4/info"))
            .and(body_json(serde_json::json!({"Username": TEST_USERNAME})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Modulus": SIGNED_MODULUS,
                "ServerEphemeral": challenge,
                "Version": 4,
                "Salt": client_verifier.salt,
                "SRPSession": "fixture-srp-session"
            })))
            .expect(1)
            .mount(server)
            .await;

        let srp_server = Mutex::new(srp_server);
        Mock::given(method("POST"))
            .and(path("/auth/v4"))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body.as_object().unwrap().len(), 4);
                assert_eq!(body["Username"], TEST_USERNAME);
                assert_eq!(body["SRPSession"], "fixture-srp-session");
                let proof = ServerClientProof::new(
                    body["ClientEphemeral"].as_str().unwrap(),
                    body["ClientProof"].as_str().unwrap(),
                )
                .unwrap();
                let mut server_proof = srp_server
                    .lock()
                    .unwrap()
                    .verify_proof(&proof)
                    .unwrap()
                    .encode_b64();
                if corrupt_server_proof {
                    // Preserve valid base64 and length while making the proof incorrect.
                    let replacement = if server_proof.starts_with('A') {
                        "B"
                    } else {
                        "A"
                    };
                    server_proof.replace_range(..1, replacement);
                }
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "Code": 1000,
                    "UID": "fixture-uid",
                    "AccessToken": "fixture-access",
                    "RefreshToken": "fixture-refresh",
                    "ServerProof": server_proof,
                    "2FA": {"Enabled": two_fa},
                    "PasswordMode": 2
                }))
            })
            .expect(1)
            .mount(server)
            .await;
    }

    async fn client_with_prior_session(server: &MockServer) -> HttpClient {
        let http = HttpClient::new(server.uri(), "fixture-app-version");
        http.set_user_agent("fixture-user-agent".into()).await;
        http.set_tokens(
            "prior-uid".into(),
            SecretString::from("prior-access"),
            SecretString::from("prior-refresh"),
        )
        .await;
        http
    }

    fn assert_unauthenticated(request: &wiremock::Request) {
        assert!(request.headers.get("authorization").is_none());
        assert!(request.headers.get("x-pm-uid").is_none());
        assert!(request.headers.get("x-enforce-unauthsession").is_none());
    }

    #[tokio::test]
    async fn login_uses_canonical_unauthenticated_sequence_then_authenticated_totp() {
        let server = MockServer::start().await;
        mock_srp_login(&server, 1, false).await;
        Mock::given(method("POST"))
            .and(path("/auth/v4/2fa"))
            .and(body_json(serde_json::json!({"TwoFactorCode": "123456"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"Code": 1000})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let http = client_with_prior_session(&server).await;
        let result = login(
            &http,
            TEST_USERNAME,
            &SecretString::from(TEST_PASSWORD),
            Some("123456"),
        )
        .await
        .unwrap();
        assert_eq!(result.tokens.uid, "fixture-uid");
        assert_eq!(result.tokens.access.expose_secret(), "fixture-access");
        assert_eq!(result.tokens.refresh.expose_secret(), "fixture-refresh");
        assert_eq!(result.password_mode, 2);

        let requests = server.received_requests().await.unwrap();
        let paths: Vec<_> = requests.iter().map(|r| r.url.path()).collect();
        assert_eq!(paths, ["/auth/v4/info", "/auth/v4", "/auth/v4/2fa"]);
        for request in &requests {
            assert_eq!(request.method.as_str(), "POST");
            assert_eq!(request.headers["x-pm-appversion"], "fixture-app-version");
            assert_eq!(request.headers["user-agent"], "fixture-user-agent");
        }
        assert_unauthenticated(&requests[0]);
        assert_unauthenticated(&requests[1]);
        assert_eq!(
            requests[2].headers["authorization"],
            "Bearer fixture-access"
        );
        assert_eq!(requests[2].headers["x-pm-uid"], "fixture-uid");
    }

    #[tokio::test]
    async fn invalid_server_proof_does_not_accept_tokens_or_submit_totp() {
        let server = MockServer::start().await;
        mock_srp_login(&server, 1, true).await;
        let http = client_with_prior_session(&server).await;
        let result = login(
            &http,
            TEST_USERNAME,
            &SecretString::from(TEST_PASSWORD),
            Some("123456"),
        )
        .await;
        assert!(
            matches!(result, Err(Error::Srp(message)) if message == "server proof verification failed")
        );
        let state = http.auth_state();
        let state = state.read().await;
        assert_eq!(state.uid.as_deref(), Some("prior-uid"));
        assert_eq!(
            state.access.as_ref().unwrap().expose_secret(),
            "prior-access"
        );
        assert_eq!(
            state.refresh.as_ref().unwrap().expose_secret(),
            "prior-refresh"
        );

        let requests = server.received_requests().await.unwrap();
        let paths: Vec<_> = requests.iter().map(|r| r.url.path()).collect();
        assert_eq!(paths, ["/auth/v4/info", "/auth/v4"]);
        for request in &requests {
            assert_unauthenticated(request);
        }
    }

    #[tokio::test]
    async fn invalid_modulus_signature_aborts_before_submitting_proof() {
        let server = MockServer::start().await;
        let corrupted_modulus = SIGNED_MODULUS.replacen("W2z5", "X2z5", 1);
        Mock::given(method("POST"))
            .and(path("/auth/v4/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Modulus": corrupted_modulus,
                "ServerEphemeral": "unused",
                "Version": 4,
                "Salt": "unused",
                "SRPSession": "fixture-srp-session"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let http = client_with_prior_session(&server).await;
        let result = login(
            &http,
            TEST_USERNAME,
            &SecretString::from(TEST_PASSWORD),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(Error::Srp(message)) if message.contains("Modulus signature verification failed"))
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/auth/v4/info");
        assert_unauthenticated(&requests[0]);
    }

    #[tokio::test]
    async fn rejected_auth_info_does_not_refresh_or_retry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v4/info"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "Code": 8002, "Error": "fixture rejection"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let http = client_with_prior_session(&server).await;
        assert!(login(
            &http,
            TEST_USERNAME,
            &SecretString::from(TEST_PASSWORD),
            None
        )
        .await
        .is_err());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/auth/v4/info");
        assert_unauthenticated(&requests[0]);
    }

    #[tokio::test]
    async fn logout_calls_revoke() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/core/v4/auth"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"Code": 1000})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let http = HttpClient::new(server.uri(), "Other");
        logout(&http).await.unwrap();
    }
}
