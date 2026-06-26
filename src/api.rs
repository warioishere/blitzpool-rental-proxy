//! HTTP/JSON control API — the proxy is fully steerable through this. The
//! existing web UI calls these endpoints; no UI is built here.
//!
//!   GET  /api/health
//!   GET  /api/sessions                      list live miners + status
//!   GET  /api/sessions/{worker}             one session
//!   POST /api/sessions/{worker}/rent        body {url,user,pass,order_id,until_unix_ms}
//!   POST /api/sessions/{worker}/release     back to default pool
//!
//! Seller-config + order endpoints are added by their modules (sellers/orders).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tracing::info;

use crate::registry::Registry;
use crate::session::UpstreamTarget;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{worker}", get(get_session))
        .route("/api/sessions/{worker}/rent", post(rent))
        .route("/api/sessions/{worker}/release", post(release))
        .with_state(state)
}

pub async fn serve(addr: String, state: AppState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, "HTTP API listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

type ApiError = (StatusCode, String);

async fn health() -> Json<Value> {
    Json(json!({"ok": true, "service": "stratum-rental-proxy"}))
}

async fn list_sessions(State(s): State<AppState>) -> Json<Value> {
    Json(json!({ "sessions": s.registry.snapshot().await }))
}

async fn get_session(
    State(s): State<AppState>,
    Path(worker): Path<String>,
) -> Result<Json<Value>, ApiError> {
    match s.registry.get(&worker).await {
        Some(sess) => Ok(Json(json!(sess.status().await))),
        None => Err((StatusCode::NOT_FOUND, "worker not connected".into())),
    }
}

#[derive(Deserialize)]
struct RentReq {
    url: String,
    user: String,
    #[serde(default)]
    pass: String,
    #[serde(default)]
    order_id: Option<String>,
    #[serde(default)]
    until_unix_ms: i64,
}

async fn rent(
    State(s): State<AppState>,
    Path(worker): Path<String>,
    Json(req): Json<RentReq>,
) -> Result<Json<Value>, ApiError> {
    let sess = s
        .registry
        .get(&worker)
        .await
        .ok_or((StatusCode::NOT_FOUND, "worker not connected".to_string()))?;
    let _ = req.until_unix_ms; // honored by the orders layer
    let target = UpstreamTarget {
        url: req.url,
        user: req.user,
        password: req.pass,
    };
    sess.switch_to(req.order_id.unwrap_or_default(), target)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(json!({"ok": true})))
}

async fn release(
    State(s): State<AppState>,
    Path(worker): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let sess = s
        .registry
        .get(&worker)
        .await
        .ok_or((StatusCode::NOT_FOUND, "worker not connected".to_string()))?;
    sess.revert()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(json!({"ok": true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        router(AppState {
            registry: Registry::new(),
        })
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = app()
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_sessions_empty() {
        let resp = app()
            .oneshot(Request::get("/api/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["sessions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rent_unknown_worker_is_404() {
        let req = Request::post("/api/sessions/ghost/rent")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"x:1","user":"u"}"#))
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn release_unknown_worker_is_404() {
        let resp = app()
            .oneshot(
                Request::post("/api/sessions/ghost/release")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
