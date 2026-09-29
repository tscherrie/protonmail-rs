//! Bearer authentication and browser-origin rejection for machine clients.
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub(crate) async fn authorize(
    State(token): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if request.headers().contains_key("origin") {
        return Err(StatusCode::FORBIDDEN);
    }
    let supplied = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bool::from(supplied.as_bytes().ct_eq(token.as_bytes())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

pub(crate) fn load_token(path: &std::path::Path) -> anyhow::Result<Arc<String>> {
    let value = std::fs::read_to_string(path)?;
    let token = value.trim();
    anyhow::ensure!(
        token.len() >= 32 && token.len() <= 256 && token.bytes().all(|b| b.is_ascii_graphic()),
        "HTTP bearer token must contain 32-256 printable characters without whitespace"
    );
    Ok(Arc::new(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_unauthenticated_and_browser_requests() {
        let token = Arc::new("test-token-at-least-thirty-two-characters".to_owned());
        let app = axum::Router::new()
            .route("/mcp", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                token.clone(),
                authorize,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let c = reqwest::Client::new();
        assert_eq!(c.get(&url).send().await.unwrap().status(), 401);
        assert_eq!(
            c.get(&url)
                .bearer_auth("wrong")
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            c.get(&url)
                .bearer_auth(token.as_str())
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            c.get(&url)
                .bearer_auth(token.as_str())
                .header("origin", "https://untrusted.invalid")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        task.abort();
    }
}
