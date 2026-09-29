//! Request header construction.

use super::{AuthState, Request};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use secrecy::ExposeSecret;

/// Build the Proton headers for a request given the current auth state.
pub fn build_headers(auth: &AuthState, req: &Request) -> HeaderMap {
    let mut h = HeaderMap::new();

    let content_type = req.content_type.as_deref().unwrap_or("application/json");
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(reqwest::header::CONTENT_TYPE, v);
    }

    if let Ok(v) = HeaderValue::from_str(&auth.app_version) {
        h.insert(HeaderName::from_static("x-pm-appversion"), v);
    }

    if let Some(ua) = &auth.user_agent {
        if let Ok(v) = HeaderValue::from_str(ua) {
            h.insert(reqwest::header::USER_AGENT, v);
        }
    }

    if let Some(uid) = auth.uid.as_ref().filter(|_| !req.omit_uid) {
        if let Ok(v) = HeaderValue::from_str(uid) {
            h.insert(HeaderName::from_static("x-pm-uid"), v);
        }
    }

    if let Some(token) = auth.access.as_ref().filter(|_| !req.omit_auth) {
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", token.expose_secret())) {
            h.insert(reqwest::header::AUTHORIZATION, v);
        }
    }

    if let Some((token, ttype)) = &req.hv {
        if let (Ok(tv), Ok(tt)) = (HeaderValue::from_str(token), HeaderValue::from_str(ttype)) {
            h.insert(HeaderName::from_static("x-pm-human-verification-token"), tv);
            h.insert(
                HeaderName::from_static("x-pm-human-verification-token-type"),
                tt,
            );
        }
    }

    if req.enforce_unauth {
        h.insert(
            HeaderName::from_static("x-enforce-unauthsession"),
            HeaderValue::from_static("true"),
        );
    }

    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Body, Request};
    use reqwest::Method;
    use secrecy::SecretString;

    fn auth() -> AuthState {
        AuthState {
            uid: Some("UID123".into()),
            access: Some(SecretString::from("ACCESS")),
            refresh: None,
            app_version: "Other".into(),
            user_agent: Some("Mozilla/5.0 test-ua".into()),
        }
    }

    #[test]
    fn sets_core_headers() {
        let req = Request::new(Method::GET, "/x");
        let h = build_headers(&auth(), &req);
        assert_eq!(h.get("x-pm-uid").unwrap(), "UID123");
        assert_eq!(h.get("authorization").unwrap(), "Bearer ACCESS");
        assert_eq!(h.get("x-pm-appversion").unwrap(), "Other");
        assert_eq!(h.get("content-type").unwrap(), "application/json");
        assert_eq!(h.get("user-agent").unwrap(), "Mozilla/5.0 test-ua");
        assert!(h.get("x-pm-human-verification-token").is_none());
    }

    #[test]
    fn hv_headers_present_when_set() {
        let req = Request::new(Method::POST, "/x").with_hv("tok", "captcha");
        let h = build_headers(&auth(), &req);
        assert_eq!(h.get("x-pm-human-verification-token").unwrap(), "tok");
        assert_eq!(
            h.get("x-pm-human-verification-token-type").unwrap(),
            "captcha"
        );
    }

    #[test]
    fn omits_auth_when_unset() {
        let a = AuthState {
            uid: None,
            access: None,
            refresh: None,
            app_version: "Other".into(),
            user_agent: None,
        };
        let h = build_headers(&a, &Request::new(Method::GET, "/x"));
        assert!(h.get("x-pm-uid").is_none());
        assert!(h.get("authorization").is_none());
        assert!(h.get("user-agent").is_none());
    }

    #[test]
    fn initial_auth_omits_both_session_headers_but_refresh_retains_uid() {
        let initial = build_headers(&auth(), &Request::post("/auth/v4/info").unauthenticated());
        assert!(!initial.contains_key("authorization"));
        assert!(!initial.contains_key("x-pm-uid"));
        assert!(!initial.contains_key("x-enforce-unauthsession"));
        assert_eq!(initial.get("x-pm-appversion").unwrap(), "Other");
        let refresh = build_headers(&auth(), &Request::post("/auth/v4/refresh").omit_auth());
        assert!(!refresh.contains_key("authorization"));
        assert_eq!(refresh.get("x-pm-uid").unwrap(), "UID123");
    }

    #[test]
    fn custom_content_type() {
        let req =
            Request::new(Method::POST, "/x").raw(vec![1, 2, 3], "multipart/form-data; boundary=z");
        let h = build_headers(&auth(), &req);
        assert_eq!(
            h.get("content-type").unwrap(),
            "multipart/form-data; boundary=z"
        );
        let _ = Body::Empty;
    }
}
