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
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tracing::info;

use crate::registry::Registry;
use crate::session::UpstreamTarget;
use crate::store::SellerStore;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub sellers: Arc<SellerStore>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{worker}", get(get_session))
        .route("/api/sessions/{worker}/rent", post(rent))
        .route("/api/sessions/{worker}/release", post(release))
        .route("/api/sellers", get(list_sellers))
        .route(
            "/api/sellers/{worker}",
            put(set_seller).delete(delete_seller),
        )
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

async fn list_sellers(State(s): State<AppState>) -> Json<Value> {
    Json(json!({ "sellers": s.sellers.list().await }))
}

#[derive(Deserialize)]
struct SellerReq {
    url: String,
    user: String,
    #[serde(default)]
    pass: String,
}

/// Set a seller's default pool. Applies to the next connect; if the worker is
/// connected and idle, the change is pushed live.
async fn set_seller(
    State(s): State<AppState>,
    Path(worker): Path<String>,
    Json(req): Json<SellerReq>,
) -> Result<Json<Value>, ApiError> {
    let target = UpstreamTarget {
        url: req.url,
        user: req.user,
        password: req.pass,
    };
    s.sellers
        .set(worker.clone(), target.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // If connected + idle, apply now.
    if let Some(sess) = s.registry.get(&worker).await {
        let routing = sess.status().await.routing;
        if routing == "idle" {
            let _ = sess.set_default(target).await;
        }
    }
    Ok(Json(json!({"ok": true})))
}

async fn delete_seller(
    State(s): State<AppState>,
    Path(worker): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let removed = s
        .sellers
        .remove(&worker)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "removed": removed})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn app() -> Router {
        let p = std::env::temp_dir().join(format!("srp_api_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        router(AppState {
            registry: Registry::new(),
            sellers: SellerStore::load(p).await,
        })
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = app()
            .await
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_sessions_empty() {
        let resp = app()
            .await
            .oneshot(Request::get("/api/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["sessions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rent_unknown_worker_is_404() {
        let req = Request::post("/api/sessions/ghost/rent")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"x:1","user":"u"}"#))
            .unwrap();
        let resp = app().await.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn release_unknown_worker_is_404() {
        let resp = app()
            .await
            .oneshot(
                Request::post("/api/sessions/ghost/release")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sellers_set_then_list() {
        let app = app().await;
        let put = Request::put("/api/sellers/bc1qSELLER.rig1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"poolA:3333","user":"acct","pass":"x"}"#))
            .unwrap();
        let resp = app.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(Request::get("/api/sellers").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["url"], "poolA:3333");
    }
}
