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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use tracing::info;

use crate::orders::{now_ms, OrderStore};
use crate::registry::Registry;
use crate::session::UpstreamTarget;
use crate::store::{Rig, SellerStore};

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub sellers: Arc<SellerStore>,
    pub orders: Arc<OrderStore>,
    /// Bearer token required on every endpoint except `/api/health`. Empty =
    /// not configured → the API fails closed (rejects all). See [`require_bearer`].
    pub api_token: Arc<str>,
}

pub fn router(state: AppState) -> Router {
    // Everything except health requires a valid bearer token. The pool sits
    // behind pfSense (TLS termination); auth here is what keeps the control
    // API safe to expose.
    let protected = Router::new()
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{worker}", get(get_session))
        .route("/api/sessions/{worker}/rent", post(rent))
        .route("/api/sessions/{worker}/release", post(release))
        .route("/api/sellers", get(list_sellers))
        .route(
            "/api/sellers/{worker}",
            put(set_seller).delete(delete_seller),
        )
        .route("/api/sellers/{worker}/rentable", post(set_rentable))
        .route("/api/orders", get(list_orders).post(create_order))
        .route("/api/orders/{id}", get(get_order).delete(cancel_order))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_bearer));

    Router::new()
        .route("/api/health", get(health))
        .merge(protected)
        .with_state(state)
}

/// Bearer-token gate for the control API. The token comes from
/// `RENTAL_PROXY_API_TOKEN`; if it is unset the API fails closed (rejects
/// everything) so it can never be accidentally exposed unauthenticated.
async fn require_bearer(
    State(s): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Result<axum::response::Response, ApiError> {
    if s.api_token.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "control API token not configured (set RENTAL_PROXY_API_TOKEN)".into(),
        ));
    }
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if ct_eq(presented, &s.api_token) {
        Ok(next.run(req).await)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token".into(),
        ))
    }
}

/// Constant-time string compare — avoids leaking the token via response timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
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
    match s.registry.aggregated_status(&worker).await {
        Some(status) => Ok(Json(json!(status))),
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
    let sessions = s.registry.get_all(&worker).await;
    if sessions.is_empty() {
        return Err((StatusCode::NOT_FOUND, "worker not connected".to_string()));
    }
    let _ = req.until_unix_ms; // honored by the orders layer
    let target = UpstreamTarget {
        url: req.url,
        user: req.user,
        password: req.pass,
        authority_pubkey: req.authority,
    };
    let order_id = req.order_id.unwrap_or_default();
    // Switch every miner of this rig to the buyer's target.
    let switched = switch_all(&sessions, &order_id, &target).await;
    if switched == 0 {
        return Err((StatusCode::BAD_GATEWAY, "no session could be switched".into()));
    }
    Ok(Json(json!({"ok": true, "switched": switched, "of": sessions.len()})))
}

/// Switch all of a rig's sessions to `target`; returns how many succeeded.
/// Tolerates partial failure (a dead session's reconnect resumes the order),
/// but logs it.
async fn switch_all(
    sessions: &[crate::control::AnySession],
    order_id: &str,
    target: &UpstreamTarget,
) -> usize {
    let mut ok = 0;
    for sess in sessions {
        match sess.switch_to(order_id.to_string(), target.clone()).await {
            Ok(()) => ok += 1,
            Err(e) => tracing::warn!(error = %e, "rig session switch failed"),
        }
    }
    ok
}

/// Revert all of a rig's sessions to their default pool; returns how many succeeded.
async fn revert_all(sessions: &[crate::control::AnySession]) -> usize {
    let mut ok = 0;
    for sess in sessions {
        match sess.revert().await {
            Ok(()) => ok += 1,
            Err(e) => tracing::warn!(error = %e, "rig session revert failed"),
        }
    }
    ok
}

async fn release(
    State(s): State<AppState>,
    Path(worker): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let sessions = s.registry.get_all(&worker).await;
    if sessions.is_empty() {
        return Err((StatusCode::NOT_FOUND, "worker not connected".to_string()));
    }
    let reverted = revert_all(&sessions).await;
    Ok(Json(json!({"ok": true, "reverted": reverted, "of": sessions.len()})))
}

#[derive(Deserialize)]
struct SellerQuery {
    /// Filter to one seller's rigs (`<address>` + its `<address>.<label>` rigs).
    #[serde(default)]
    seller: Option<String>,
}

/// A rig is rentable only while it's actually delivering hashrate. The live
/// windowed estimate reads 0 h/s when a worker is disconnected or hasn't landed
/// an accepted share recently, so `> 0` means "online and delivering".
fn is_delivering(hashrate_hs: f64) -> bool {
    hashrate_hs > 0.0
}

/// Merge each rig with its live status (`online`, `hashrate_hs`, `rented`),
/// keyed by worker. `live` maps currently-connected workers to their windowed
/// hashrate estimate (hashes/second); a worker absent from `live` is offline.
/// `rented` is the set of workers with an active rental order.
fn enrich_sellers(
    sellers: HashMap<String, Rig>,
    live: &HashMap<String, f64>,
    rented: &HashSet<String>,
) -> Map<String, Value> {
    sellers
        .into_iter()
        .map(|(worker, rig)| {
            let hashrate_hs = live.get(&worker).copied().unwrap_or(0.0);
            let mut v = serde_json::to_value(&rig).unwrap_or_else(|_| json!({}));
            if let Value::Object(map) = &mut v {
                map.insert("hashrate_hs".into(), json!(hashrate_hs));
                map.insert("online".into(), json!(is_delivering(hashrate_hs)));
                map.insert("rented".into(), json!(rented.contains(&worker)));
            }
            (worker, v)
        })
        .collect()
}

/// List rigs. `?seller=<address>` filters to that seller's rigs (dashboard);
/// no filter returns all (operator view). Each rig carries live `online`,
/// `hashrate_hs` and `rented` derived from the connected sessions + orders.
async fn list_sellers(State(s): State<AppState>, Query(q): Query<SellerQuery>) -> Json<Value> {
    let sellers = match q.seller.as_deref() {
        Some(addr) if !addr.is_empty() => s.sellers.list_for_seller(addr).await,
        _ => s.sellers.list().await,
    };
    let live: HashMap<String, f64> = s
        .registry
        .snapshot()
        .await
        .into_iter()
        .map(|st| (st.worker, st.hashrate_hs))
        .collect();
    let now = now_ms();
    let rented: HashSet<String> = s
        .orders
        .list()
        .await
        .into_iter()
        .filter(|o| o.is_live(now))
        .map(|o| o.worker)
        .collect();
    Json(json!({ "sellers": enrich_sellers(sellers, &live, &rented) }))
}

fn default_true() -> bool {
    true
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
    /// Whether the rig is listed for rent (default true). The rig still
    /// idle-mines when false; it just can't be rented.
    #[serde(default = "default_true")]
    rentable: bool,
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
        rentable: req.rentable,
    };
    s.sellers
        .set(worker.clone(), rig)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // If connected + idle, apply the new default pool now — to every miner of
    // the rig (a rented session keeps its buyer target).
    for sess in s.registry.get_all(&worker).await {
        if sess.status().await.routing == "idle" {
            let _ = sess.set_default(target.clone()).await;
        }
    }
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct RentableReq {
    rentable: bool,
}

/// Toggle whether a rig is listed for rent (marketplace on/off). The rig keeps
/// idle-mining either way; `false` just blocks new rentals.
async fn set_rentable(
    State(s): State<AppState>,
    Path(worker): Path<String>,
    Json(req): Json<RentableReq>,
) -> Result<Json<Value>, ApiError> {
    let updated = s
        .sellers
        .set_rentable(&worker, req.rentable)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !updated {
        return Err((StatusCode::NOT_FOUND, "rig not found".into()));
    }
    Ok(Json(json!({"ok": true, "rentable": req.rentable})))
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
) -> Result<Json<Value>, ApiError> {
    // A registered rig that's toggled off can't be rented.
    if let Some(rig) = s.sellers.get(&req.worker).await {
        if !rig.rentable {
            return Err((StatusCode::CONFLICT, "rig is not listed for rent".into()));
        }
    }
    // An already-rented rig (live order) can't be rented again.
    if s.orders.active_for_worker(&req.worker, now_ms()).await.is_some() {
        return Err((StatusCode::CONFLICT, "rig is already rented".into()));
    }
    // Only rigs currently delivering hashrate can be rented (summed across all
    // of the rig's miners).
    let live_hashrate = s
        .registry
        .aggregated_status(&req.worker)
        .await
        .map(|st| st.hashrate_hs)
        .unwrap_or(0.0);
    if !is_delivering(live_hashrate) {
        return Err((StatusCode::CONFLICT, "rig is offline".into()));
    }
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
    let sessions = s.registry.get_all(&req.worker).await;
    let switched = switch_all(&sessions, &order.id, &target).await;
    let applied = switched > 0;
    Ok(Json(json!({
        "ok": true,
        "order": order_json(&order),
        "applied": applied,
        "switched": switched,
        "of": sessions.len(),
    })))
}

/// Cancel an order; if the worker is connected, revert it to its default pool.
async fn cancel_order(State(s): State<AppState>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let order = s
        .orders
        .cancel(&id)
        .await
        .ok_or((StatusCode::NOT_FOUND, "order not found".to_string()))?;
    let sessions = s.registry.get_all(&order.worker).await;
    let reverted = revert_all(&sessions).await;
    Ok(Json(json!({"ok": true, "reverted": reverted, "of": sessions.len()})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TOKEN: &str = "testtoken";
    const BEARER: &str = "Bearer testtoken";

    async fn app_token(token: &str) -> Router {
        let pool = crate::db::test_pool().await;
        router(AppState {
            registry: Registry::new(),
            sellers: SellerStore::new(pool.clone()),
            orders: crate::orders::OrderStore::new(pool),
            api_token: token.into(),
        })
    }

    async fn app() -> Router {
        app_token(TOKEN).await
    }

    /// App plus a handle to its order store, to seed rentals directly in tests.
    async fn app_with_orders() -> (Router, Arc<OrderStore>) {
        let pool = crate::db::test_pool().await;
        let orders = OrderStore::new(pool.clone());
        let app = router(AppState {
            registry: Registry::new(),
            sellers: SellerStore::new(pool.clone()),
            orders: orders.clone(),
            api_token: TOKEN.into(),
        });
        (app, orders)
    }

    fn buyer_target() -> UpstreamTarget {
        UpstreamTarget {
            url: "buyer:3333".into(),
            user: "b".into(),
            password: "x".into(),
            authority_pubkey: None,
        }
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Plain-text body (error responses are `(StatusCode, String)`).
    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn health_is_public() {
        // No token needed for liveness checks (pfSense health probes).
        let resp = app()
            .await
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_without_token_is_401() {
        let resp = app()
            .await
            .oneshot(Request::get("/api/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_route_with_wrong_token_is_401() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/api/sessions")
                    .header("authorization", "Bearer nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unconfigured_token_fails_closed() {
        // Empty token (RENTAL_PROXY_API_TOKEN unset) → API rejects everything
        // protected, even with a bearer header.
        let resp = app_token("")
            .await
            .oneshot(
                Request::get("/api/sessions")
                    .header("authorization", "Bearer anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn list_sessions_empty() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/api/sessions")
                    .header("authorization", BEARER)
                    .body(Body::empty())
                    .unwrap(),
            )
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
            .header("authorization", BEARER)
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
                    .header("authorization", BEARER)
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
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"url":"poolA:3333","user":"acct","pass":"x","advertised_ths":220,"price_per_th_day":0.05}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(
                Request::get("/api/sellers")
                    .header("authorization", BEARER)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["default_pool"]["url"], "poolA:3333");
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["advertised_ths"], 220.0);
        // A registered rig with no connected miner is offline (not delivering).
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["online"], false);
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["hashrate_hs"], 0.0);
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["rented"], false);
    }

    #[tokio::test]
    async fn create_order_for_offline_worker_is_rejected() {
        // Only rigs currently delivering hashrate can be rented; an offline
        // worker (no connected session) is rejected and no order is recorded.
        let app = app().await;
        let post = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"worker":"bc1qSELLER.rig1","url":"buyer:3333","user":"b","pass":"x","until_ms":0}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(post).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("offline"));

        let resp = app
            .oneshot(
                Request::get("/api/orders")
                    .header("authorization", BEARER)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["orders"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn create_order_for_already_rented_worker_is_rejected() {
        // A worker with a live rental can't be rented again, even while online.
        let (app, orders) = app_with_orders().await;
        orders
            .create("bc1qA.rig1".to_string(), buyer_target(), 0, 0.0, 0.0)
            .await;

        let post = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"worker":"bc1qA.rig1","url":"buyer2:3333","user":"c","until_ms":0}"#,
            ))
            .unwrap();
        let resp = app.oneshot(post).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("already rented"));
    }

    #[test]
    fn is_delivering_requires_positive_hashrate() {
        assert!(!is_delivering(0.0));
        assert!(is_delivering(1.0));
        assert!(is_delivering(5.0e12));
    }

    #[test]
    fn enrich_sellers_marks_online_only_when_delivering() {
        let mut sellers = HashMap::new();
        sellers.insert(
            "bc1qA.on".to_string(),
            Rig { advertised_ths: 100.0, ..Default::default() },
        );
        sellers.insert("bc1qA.off".to_string(), Rig::default());

        let mut live = HashMap::new();
        live.insert("bc1qA.on".to_string(), 5.0e12);
        // "bc1qA.off" absent from the live map → offline.

        let out = enrich_sellers(sellers, &live, &HashSet::new());
        assert_eq!(out["bc1qA.on"]["online"], json!(true));
        assert_eq!(out["bc1qA.on"]["hashrate_hs"], json!(5.0e12));
        assert_eq!(out["bc1qA.on"]["advertised_ths"], json!(100.0));
        assert_eq!(out["bc1qA.on"]["rented"], json!(false));
        assert_eq!(out["bc1qA.off"]["online"], json!(false));
        assert_eq!(out["bc1qA.off"]["hashrate_hs"], json!(0.0));
        assert_eq!(out["bc1qA.off"]["rented"], json!(false));
    }

    #[test]
    fn enrich_sellers_marks_rented() {
        let mut sellers = HashMap::new();
        sellers.insert("bc1qA.rig1".to_string(), Rig::default());

        let mut live = HashMap::new();
        live.insert("bc1qA.rig1".to_string(), 5.0e12); // online + delivering
        let mut rented = HashSet::new();
        rented.insert("bc1qA.rig1".to_string()); // but already rented

        let out = enrich_sellers(sellers, &live, &rented);
        assert_eq!(out["bc1qA.rig1"]["online"], json!(true));
        assert_eq!(out["bc1qA.rig1"]["rented"], json!(true));
    }

    async fn put_rig(app: &Router, worker: &str) {
        let put = Request::put(format!("/api/sellers/{worker}"))
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(r#"{"url":"poolA:3333","user":"acct"}"#))
            .unwrap();
        let resp = app.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_sellers_filtered_by_seller() {
        let app = app().await;
        put_rig(&app, "bc1qA").await;
        put_rig(&app, "bc1qA.rig1").await;
        put_rig(&app, "bc1qB.rig1").await;

        let resp = app
            .oneshot(
                Request::get("/api/sellers?seller=bc1qA")
                    .header("authorization", BEARER)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v = body_json(resp).await;
        let sellers = v["sellers"].as_object().unwrap();
        assert_eq!(sellers.len(), 2, "bc1qA + bc1qA.rig1");
        assert!(sellers.contains_key("bc1qA"));
        assert!(sellers.contains_key("bc1qA.rig1"));
        assert!(!sellers.contains_key("bc1qB.rig1"));
    }

    #[tokio::test]
    async fn rentable_toggle_blocks_new_rentals() {
        let app = app().await;
        put_rig(&app, "bc1qA.rig1").await;

        // Toggle off.
        let off = Request::post("/api/sellers/bc1qA.rig1/rentable")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(r#"{"rentable":false}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(off).await.unwrap().status(), StatusCode::OK);

        // Creating a rental for a non-rentable rig is rejected by the rentable gate.
        let order = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"worker":"bc1qA.rig1","url":"buyer:3333","user":"b","until_ms":0}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(order).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("not listed for rent"));

        // Toggle back on → the rentable gate no longer blocks. The rig is still
        // offline (no connected miner), so it's now rejected for that reason —
        // proving the toggle worked (the rejection reason changed).
        let on = Request::post("/api/sellers/bc1qA.rig1/rentable")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(r#"{"rentable":true}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(on).await.unwrap().status(), StatusCode::OK);

        let order2 = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"worker":"bc1qA.rig1","url":"buyer:3333","user":"b","until_ms":0}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(order2).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("offline"));
    }

    #[tokio::test]
    async fn rentable_toggle_unknown_rig_is_404() {
        let resp = app()
            .await
            .oneshot(
                Request::post("/api/sellers/ghost/rentable")
                    .header("content-type", "application/json")
                    .header("authorization", BEARER)
                    .body(Body::from(r#"{"rentable":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
