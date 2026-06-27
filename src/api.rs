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

use crate::orders::OrderStore;
use crate::registry::Registry;
use crate::session::UpstreamTarget;
use crate::store::SellerStore;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub sellers: Arc<SellerStore>,
    pub orders: Arc<OrderStore>,
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
        .route("/api/orders", get(list_orders).post(create_order))
        .route("/api/orders/{id}", get(get_order).delete(cancel_order))
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
    /// SV2 only: pool Noise authority public key (base58).
    #[serde(default)]
    authority: Option<String>,
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
        authority_pubkey: req.authority,
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
    /// Idle/default pool.
    url: String,
    user: String,
    #[serde(default)]
    pass: String,
    /// SV2 only: pool Noise authority public key (base58).
    #[serde(default)]
    authority: Option<String>,
    /// Marketplace listing: advertised hashrate + pricing.
    #[serde(default)]
    advertised_ths: f64,
    #[serde(default)]
    price_per_th_day: f64,
    #[serde(default)]
    price_min_per_th_day: f64,
    #[serde(default)]
    price_max_per_th_day: f64,
    /// Seller payout address (e.g. BTC) for rental earnings.
    #[serde(default)]
    payout_address: Option<String>,
}

/// Register/update a seller's rig: idle/default pool plus the marketplace
/// listing (advertised hashrate + price). Applies the default pool live if the
/// worker is connected and idle.
async fn set_seller(
    State(s): State<AppState>,
    Path(worker): Path<String>,
    Json(req): Json<SellerReq>,
) -> Result<Json<Value>, ApiError> {
    let target = UpstreamTarget {
        url: req.url,
        user: req.user,
        password: req.pass,
        authority_pubkey: req.authority,
    };
    let rig = crate::store::Rig {
        default_pool: target.clone(),
        advertised_ths: req.advertised_ths,
        price_per_th_day: req.price_per_th_day,
        price_min_per_th_day: req.price_min_per_th_day,
        price_max_per_th_day: req.price_max_per_th_day,
        payout_address: req.payout_address,
    };
    s.sellers
        .set(worker.clone(), rig)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // If connected + idle, apply the default pool now.
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

/// Serialize an order plus its computed billing fields (measured cost so far +
/// remaining prepaid budget).
fn order_json(o: &crate::orders::Order) -> Value {
    let mut v = serde_json::to_value(o).unwrap_or_else(|_| json!({}));
    v["cost"] = json!(o.cost());
    v["budget_remaining"] = json!(o.budget_remaining());
    v
}

async fn list_orders(State(s): State<AppState>) -> Json<Value> {
    let orders: Vec<Value> = s.orders.list().await.iter().map(order_json).collect();
    Json(json!({ "orders": orders }))
}

async fn get_order(State(s): State<AppState>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    match s.orders.get(&id).await {
        Some(o) => Ok(Json(order_json(&o))),
        None => Err((StatusCode::NOT_FOUND, "order not found".into())),
    }
}

#[derive(Deserialize)]
struct OrderReq {
    worker: String,
    url: String,
    user: String,
    #[serde(default)]
    pass: String,
    /// SV2 only: pool Noise authority public key (base58).
    #[serde(default)]
    authority: Option<String>,
    /// Auto-revert deadline in epoch ms; `0`/absent = open-ended.
    #[serde(default)]
    until_ms: i64,
    /// Agreed price per TH/day (same unit as `budget`, e.g. sats).
    #[serde(default)]
    price_per_th_day: f64,
    /// Prepaid credit allocated to this rental; `0` = no limit. The proxy stops
    /// routing (pay-as-you-hash) once the measured cost reaches it. No refunds.
    #[serde(default)]
    budget: f64,
}

/// Create a rental order: records it and, if the worker is connected, switches
/// its hashrate to the buyer's target now. `applied=false` means the order is
/// stored and will take effect when the miner connects.
async fn create_order(
    State(s): State<AppState>,
    Json(req): Json<OrderReq>,
) -> Json<Value> {
    let target = UpstreamTarget {
        url: req.url,
        user: req.user,
        password: req.pass,
        authority_pubkey: req.authority,
    };
    let order = s
        .orders
        .create(
            req.worker.clone(),
            target.clone(),
            req.until_ms,
            req.price_per_th_day,
            req.budget,
        )
        .await;
    let mut applied = false;
    if let Some(sess) = s.registry.get(&req.worker).await {
        applied = sess.switch_to(order.id.clone(), target).await.is_ok();
    }
    Json(json!({"ok": true, "order": order_json(&order), "applied": applied}))
}

/// Cancel an order; if the worker is connected, revert it to its default pool.
async fn cancel_order(State(s): State<AppState>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let order = s
        .orders
        .cancel(&id)
        .await
        .ok_or((StatusCode::NOT_FOUND, "order not found".to_string()))?;
    let mut reverted = false;
    if let Some(sess) = s.registry.get(&order.worker).await {
        reverted = sess.revert().await.is_ok();
    }
    Ok(Json(json!({"ok": true, "reverted": reverted})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn app() -> Router {
        let pool = crate::db::test_pool().await;
        router(AppState {
            registry: Registry::new(),
            sellers: SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool),
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
            .body(Body::from(
                r#"{"url":"poolA:3333","user":"acct","pass":"x","advertised_ths":220,"price_per_th_day":0.05}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(Request::get("/api/sellers").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["default_pool"]["url"], "poolA:3333");
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["advertised_ths"], 220.0);
    }

    #[tokio::test]
    async fn create_order_for_offline_worker_is_recorded_not_applied() {
        let app = app().await;
        let post = Request::post("/api/orders")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"worker":"bc1qSELLER.rig1","url":"buyer:3333","user":"b","pass":"x","until_ms":0}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(post).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["applied"], false); // worker not connected
        assert_eq!(v["order"]["worker"], "bc1qSELLER.rig1");

        let resp = app
            .oneshot(Request::get("/api/orders").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["orders"].as_array().unwrap().len(), 1);
    }
}
