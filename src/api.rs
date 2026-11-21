// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP/JSON control API — the proxy is fully steerable through this. The
//! existing web UI calls these endpoints; no UI is built here.
//!
//!   GET  /api/health
//!   GET  /api/sessions                      list live miners + status
//!   GET  /api/sessions/{worker}             one session
//!
//!   GET|PUT|DELETE /api/sellers[/{worker}]   rig registration + listing
//!   POST /api/sellers/{worker}/rentable      list/unlist a rig
//!   GET  /api/sellers/{worker}/history       hashrate + rental history
//!   GET|POST|DELETE /api/orders[/{id}]       rentals
//!   PUT  /api/orders/{id}/pools             replace a running rental's pools
//!
//! Rentals are driven through the orders layer (`POST /api/orders`), which gates,
//! records, bills and auto-reverts. There is no raw session-switch endpoint.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use tracing::info;

use crate::chain::Electrum;
use crate::hashrate::HashrateStore;
use crate::orders::{now_ms, OrderStatus, OrderStore};
use crate::probe::{probe_pools, PoolRefusal};
use crate::proto::sv2::relay::Sv2RigRegistry;
use crate::registry::Registry;
use crate::session::UpstreamTarget;
use crate::store::{Rig, SellerStore};

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub sellers: Arc<SellerStore>,
    pub orders: Arc<OrderStore>,
    pub hashrate: Arc<HashrateStore>,
    /// Bearer token required on every endpoint except `/api/health`. Empty =
    /// not configured → the API fails closed (rejects all). See [`require_bearer`].
    pub api_token: Arc<str>,
    /// The Bitcoin tip source for the pool probe; `None` skips the chain check.
    pub chain: Option<Arc<Electrum>>,
    /// The SV2 bundle rigs, shared with the relays.
    pub sv2_rigs: Arc<Sv2RigRegistry>,
}

pub fn router(state: AppState) -> Router {
    // Everything except health requires a valid bearer token. TLS terminates
    // in front of the proxy; auth here is what keeps the control API safe to
    // expose.
    let protected = Router::new()
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{worker}", get(get_session))
        .route("/api/sellers", get(list_sellers))
        .route(
            "/api/sellers/{worker}",
            put(set_seller).delete(delete_seller),
        )
        .route("/api/sellers/{worker}/rentable", post(set_rentable))
        .route("/api/sellers/{worker}/history", get(get_seller_history))
        .route("/api/orders", get(list_orders).post(create_order))
        .route("/api/orders/{id}", get(get_order).delete(cancel_order))
        .route("/api/orders/{id}/pools", put(set_order_pools))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));

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

/// A rig with a live rental is frozen: its seller row is neither edited nor
/// deleted until the order ends. The live session reads the row only at
/// connect, so an edit would not reach it, and a deleted row drops the rig from
/// the hashrate history while the buyer's order still runs.
async fn rented_guard(s: &AppState, worker: &str) -> Result<(), ApiError> {
    if s.orders.active_for_worker(worker, now_ms()).await.is_some() {
        return Err((StatusCode::CONFLICT, "rig is already rented".into()));
    }
    Ok(())
}

/// [`crate::session::normalize_pool_url`] as an API rejection.
fn pool_url(raw: &str) -> Result<String, ApiError> {
    crate::session::normalize_pool_url(raw).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

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
struct HistoryQuery {
    /// How many days of history (1..=7, default 7) — the chart's 1d/3d/7d toggle.
    #[serde(default)]
    days: Option<i64>,
}

/// Per-rig history for the marketplace rig chart: 10-min delivered-hashrate
/// slots, the rental bands (each order's start → end), and the advertised
/// reference line. Offline is carried per slot (`online = false`); "not rented"
/// is simply the absence of a covering rental band.
async fn get_seller_history(
    State(s): State<AppState>,
    Path(worker): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    let rig = s
        .sellers
        .get(&worker)
        .await
        .ok_or((StatusCode::NOT_FOUND, "rig not found".to_string()))?;
    let days = q.days.unwrap_or(7).clamp(1, 7);
    let now = now_ms();
    let since = now - days * 86_400_000;

    let samples = s.hashrate.since(&worker, since).await;

    let rentals: Vec<Value> = s
        .orders
        .list_for_worker(&worker)
        .await
        .into_iter()
        .filter_map(|o| {
            // Band end: now for a live rental; the exact end for one that ended
            // after the migration; else best-effort (deadline, then start).
            let end = match &o.status {
                OrderStatus::Active => now,
                _ if o.ended_ms > 0 => o.ended_ms,
                _ if o.until_ms > 0 => o.until_ms,
                _ => o.created_ms,
            };
            if end < since {
                return None; // finished before the visible window
            }
            Some(json!({
                "id": o.id,
                "start_ms": o.created_ms,
                "end_ms": end,
                "status": o.status,
            }))
        })
        .collect();

    Ok(Json(json!({
        "worker": worker,
        "advertised_ths": rig.advertised_ths,
        "days": days,
        "samples": samples,
        "rentals": rentals,
    })))
}

/// Force every connected miner of `worker` to reconnect; returns how many
/// were connected. Each session re-resolves its upstream from current state on
/// reconnect (a new rental's buyer pool, or the idle pool after a rental
/// ends), so the caller MUST persist that state first. A clean reconnect —
/// rather than a live re-point — avoids miners that ignore a mid-session
/// extranonce change and keep wasting shares on the old pool.
async fn reconnect_all(s: &AppState, worker: &str) -> usize {
    let sessions = s.registry.get_all(worker).await;
    for sess in &sessions {
        sess.force_reconnect();
    }
    sessions.len()
}

#[derive(Deserialize)]
struct SellerQuery {
    /// Filter to one seller's rigs (`<address>` + its `<address>.<label>` rigs).
    #[serde(default)]
    seller: Option<String>,
}

/// A rig is rentable only while it's actually delivering hashrate. The live
/// windowed estimate reads 0 h/s when a worker is disconnected or hasn't sent a
/// share meeting its target recently, so `> 0` means "online and delivering".
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
    /// Optional cap on a single rental's duration, in seconds (`0` = no cap).
    /// The UI collects this in hours and converts. Enforced at order creation.
    #[serde(default)]
    max_rental_secs: i64,
}

/// Register/update a seller's rig: idle/default pool plus the marketplace
/// listing (advertised hashrate + price). Applies the default pool live if the
/// worker is connected and idle.
async fn set_seller(
    State(s): State<AppState>,
    Path(worker): Path<String>,
    Json(req): Json<SellerReq>,
) -> Result<Json<Value>, ApiError> {
    rented_guard(&s, &worker).await?;
    let target = UpstreamTarget {
        url: pool_url(&req.url)?,
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
        max_rental_secs: req.max_rental_secs.max(0),
    };
    s.sellers
        .set(worker.clone(), rig)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // If connected + idle, switch to the new default pool now — to every miner
    // of the rig (a rented session keeps its buyer target). Force a reconnect
    // (not a live re-point): the store is already updated above, so the miner
    // re-handshakes onto the new pool with a clean extranonce/difficulty.
    for sess in s.registry.get_all(&worker).await {
        if sess.status().await.routing == "idle" {
            sess.force_reconnect();
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
    rented_guard(&s, &worker).await?;
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

async fn get_order(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    match s.orders.get(&id).await {
        Some(o) => Ok(Json(order_json(&o))),
        None => Err((StatusCode::NOT_FOUND, "order not found".into())),
    }
}

/// The buyer's pools, as `POST /api/orders` takes them.
#[derive(Deserialize)]
struct PoolsReq {
    url: String,
    user: String,
    #[serde(default)]
    pass: String,
    /// SV2 only: pool Noise authority public key (base58).
    #[serde(default)]
    authority: Option<String>,
    /// Optional fallback pool used when the primary `url` is unreachable.
    /// Empty/absent = no fallback.
    #[serde(default)]
    fallback_url: String,
    #[serde(default)]
    fallback_user: String,
    #[serde(default)]
    fallback_pass: String,
    #[serde(default)]
    fallback_authority: Option<String>,
}

impl PoolsReq {
    /// The primary pool and the optional fallback, urls normalized. Empty
    /// fallback url = none.
    fn targets(self) -> Result<(UpstreamTarget, Option<UpstreamTarget>), ApiError> {
        let primary = UpstreamTarget {
            url: pool_url(&self.url)?,
            user: self.user,
            password: self.pass,
            authority_pubkey: self.authority,
        };
        let fallback = if self.fallback_url.trim().is_empty() {
            None
        } else {
            Some(UpstreamTarget {
                url: pool_url(&self.fallback_url)?,
                user: self.fallback_user,
                password: self.fallback_pass,
                authority_pubkey: self.fallback_authority,
            })
        };
        Ok((primary, fallback))
    }
}

#[derive(Deserialize)]
struct OrderReq {
    worker: String,
    #[serde(flatten)]
    pools: PoolsReq,
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

/// A refusal of an order's pools (`POST /api/orders`,
/// `PUT /api/orders/{id}/pools`): a plain API error, or a pool that failed the
/// probe.
enum Refusal {
    Api(ApiError),
    /// 422 `{error, detail, pool}`; `error` is a [`crate::probe::RefusalCode`] and `pool`
    /// names the failing pool (`"primary"` or `"fallback"`).
    Pool(&'static str, PoolRefusal),
}

impl From<ApiError> for Refusal {
    fn from(e: ApiError) -> Self {
        Refusal::Api(e)
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Refusal::Api(e) => e.into_response(),
            Refusal::Pool(pool, r) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": r.code, "detail": r.detail, "pool": pool})),
            )
                .into_response(),
        }
    }
}

/// Probe the buyer's pools as `worker` would be rented onto them.
async fn probe(
    s: &AppState,
    primary: &UpstreamTarget,
    fallback: Option<&UpstreamTarget>,
    worker: &str,
) -> Result<(), Refusal> {
    let identity = crate::proto::relay::upstream_worker(&primary.user, worker);
    let fallback_identity = fallback.map(|f| crate::proto::relay::upstream_worker(&f.user, worker));
    probe_pools(
        primary,
        &identity,
        fallback.zip(fallback_identity.as_deref()),
        s.chain.as_deref(),
    )
    .await
    .map_err(|(pool, r)| Refusal::Pool(pool, r))
}

/// Create a rental order for a delivering rig: probes the buyer's pools,
/// records the order and reconnects the rig's miners onto the buyer's pool.
/// `reconnected` counts the miners dropped.
async fn create_order(
    State(s): State<AppState>,
    Json(req): Json<OrderReq>,
) -> Result<Json<Value>, Refusal> {
    // Refuse a target the relays could never connect to before anything is
    // stored: an order on an unreachable url would leave the rig mining for
    // its seller.
    let (target, fallback) = req.pools.targets()?;
    // A bounded rental's end time must be in the future (0 = open-ended). Without
    // this a past `until_ms` would slip through the max-duration check (negative
    // duration is not "too long") and create an already-expired order.
    if req.until_ms != 0 && req.until_ms <= now_ms() {
        return Err((
            StatusCode::CONFLICT,
            "end time must be in the future".to_string(),
        )
            .into());
    }
    // A registered rig that's toggled off can't be rented; and a rig with a
    // max-duration cap rejects open-ended or too-long rentals.
    if let Some(rig) = s.sellers.get(&req.worker).await {
        if !rig.rentable {
            return Err((
                StatusCode::CONFLICT,
                "rig is not listed for rent".to_string(),
            )
                .into());
        }
        if rig.max_rental_secs > 0 {
            let max_h = rig.max_rental_secs / 3600;
            if req.until_ms <= 0 {
                return Err((
                    StatusCode::CONFLICT,
                    format!("this rig caps rentals at {max_h} h — set an end time"),
                )
                    .into());
            }
            let duration_ms = req.until_ms - now_ms();
            if duration_ms > rig.max_rental_secs.saturating_mul(1000) {
                return Err((
                    StatusCode::CONFLICT,
                    format!("rental too long — this rig caps at {max_h} h"),
                )
                    .into());
            }
        }
    }
    rented_guard(&s, &req.worker).await?;
    // Only rigs currently delivering hashrate can be rented (summed across all
    // of the rig's miners).
    let live_hashrate = s
        .registry
        .aggregated_status(&req.worker)
        .await
        .map(|st| st.hashrate_hs)
        .unwrap_or(0.0);
    if !is_delivering(live_hashrate) {
        return Err((StatusCode::CONFLICT, "rig is offline".to_string()).into());
    }
    // The buyer's pools must take this rig's work before the order exists:
    // the marketplace takes the first payment only after this returns.
    probe(&s, &target, fallback.as_ref(), &req.worker).await?;
    let order = match s
        .orders
        .create(
            req.worker.clone(),
            target.clone(),
            fallback,
            req.until_ms,
            req.price_per_th_day,
            req.budget,
        )
        .await
    {
        Ok(o) => o,
        // The DB's one-active-per-worker guard fired — a concurrent request won
        // the race between the check above and this insert.
        Err(crate::orders::CreateOrderError::AlreadyActive) => {
            return Err((StatusCode::CONFLICT, "rig is already rented".to_string()).into());
        }
        Err(crate::orders::CreateOrderError::Db(e)) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into());
        }
    };
    // Reconnect every connected miner of the rig; each lands on the new rental's
    // buyer pool (failover handled at the connect path). Billing is
    // pay-as-you-hash on measured delivered work, so a miner that doesn't come
    // back simply delivers less.
    let reconnected = reconnect_all(&s, &req.worker).await;
    Ok(Json(json!({
        "ok": true,
        "order": order_json(&order),
        "reconnected": reconnected,
    })))
}

/// Replace a running order's pools (primary and fallback, as a whole; no
/// `fallback_url` = no fallback) and move the rig's miners onto them. The
/// order keeps its id, deadline, budget and counters. The new pools are probed
/// first, as at creation; a refused pool leaves the order as it was.
/// `reconnected` counts the sessions dropped.
async fn set_order_pools(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PoolsReq>,
) -> Result<Json<Value>, Refusal> {
    let (target, fallback) = req.targets()?;
    let order = s
        .orders
        .get(&id)
        .await
        .ok_or((StatusCode::NOT_FOUND, "order not found".to_string()))?;
    let not_active = || (StatusCode::CONFLICT, "order is not active".to_string());
    if !order.is_live(now_ms()) {
        return Err(not_active().into());
    }
    if order.target == target && order.fallback == fallback {
        return Ok(Json(json!({
            "ok": true,
            "order": order_json(&order),
            "reconnected": 0,
        })));
    }
    probe(&s, &target, fallback.as_ref(), &order.worker).await?;
    let order = s
        .orders
        .set_pools(&id, &target, fallback.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(not_active)?;
    // The order is stored, so every reconnect resolves the new pools. An SV2
    // bundle rig is retired first: it is routed to this order already and
    // would take its miners back onto the replaced pool.
    let retired = s.sv2_rigs.retire(&s.registry, &order.worker).await;
    let reconnected = reconnect_all(&s, &order.worker).await + usize::from(retired);
    // Once more with the miners dropped: a share the replaced pool accepted
    // since the pools were stored would count as the new pools' first.
    let order = s.orders.restart_pool_rules(&id).await.unwrap_or(order);
    Ok(Json(json!({
        "ok": true,
        "order": order_json(&order),
        "reconnected": reconnected,
    })))
}

/// Cancel an order; if the worker is connected, revert it to its default pool.
async fn cancel_order(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let order = s
        .orders
        .cancel(&id)
        .await
        .ok_or((StatusCode::NOT_FOUND, "order not found".to_string()))?;
    let reconnected = reconnect_all(&s, &order.worker).await;
    Ok(Json(json!({"ok": true, "reconnected": reconnected})))
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
            orders: crate::orders::OrderStore::new(pool.clone()),
            hashrate: HashrateStore::new(pool),
            api_token: token.into(),
            chain: None,
            sv2_rigs: Default::default(),
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
            hashrate: HashrateStore::new(pool.clone()),
            api_token: TOKEN.into(),
            chain: None,
            sv2_rigs: Default::default(),
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
        // No token needed for liveness checks.
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
        assert_eq!(
            v["sellers"]["bc1qSELLER.rig1"]["default_pool"]["url"],
            "poolA:3333"
        );
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["advertised_ths"], 220.0);
        // A registered rig with no connected miner is offline (not delivering).
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["online"], false);
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["hashrate_hs"], 0.0);
        assert_eq!(v["sellers"]["bc1qSELLER.rig1"]["rented"], false);
    }

    #[tokio::test]
    async fn a_seller_pool_typed_with_the_miner_menu_scheme_is_stored_bare() {
        let app = app().await;
        let set = Request::put("/api/sellers/bc1qSELLER.rig1")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"url":"stratum+tcp://poolA:3333","user":"acct","pass":"x"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(set).await.unwrap().status(),
            StatusCode::OK
        );
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
        assert_eq!(
            v["sellers"]["bc1qSELLER.rig1"]["default_pool"]["url"],
            "poolA:3333"
        );
    }

    #[tokio::test]
    async fn an_order_target_the_proxy_cannot_reach_is_refused_before_it_is_stored() {
        // A scheme the proxy cannot speak is refused at the API before
        // anything is stored; the miner-menu scheme is accepted
        // (this worker is offline, so the request then fails on THAT, proving
        // the url check passed).
        let app = app().await;
        let post = |url: &str| {
            Request::post("/api/orders")
                .header("content-type", "application/json")
                .header("authorization", BEARER)
                .body(Body::from(format!(
                    r#"{{"worker":"bc1qSELLER.rig1","url":"{url}","user":"b","pass":"x","until_ms":0}}"#
                )))
                .unwrap()
        };
        let resp = app
            .clone()
            .oneshot(post("stratum+ssl://buyer:3333"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("only plain tcp"));

        let resp = app
            .clone()
            .oneshot(post("stratum+tcp://stratum.braiins.com:3333"))
            .await
            .unwrap();
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
        assert_eq!(v["orders"].as_array().unwrap().len(), 0, "nothing stored");
    }

    #[test]
    fn a_pool_refusal_is_a_422_with_its_code_and_pool() {
        let r = Refusal::Pool(
            "fallback",
            crate::probe::PoolRefusal {
                code: crate::probe::RefusalCode::AuthRefused,
                detail: "Unauthorized worker (24)".into(),
            },
        );
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let v = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_json(resp));
        assert_eq!(
            v,
            json!({"error": "pool-auth-refused", "detail": "Unauthorized worker (24)", "pool": "fallback"})
        );
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
    async fn create_order_exceeding_max_duration_is_rejected() {
        // A rig capped at 1h rejects both a too-long rental and an open-ended one.
        let app = app().await;
        let set = Request::put("/api/sellers/bc1qSELLER.rig1")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"url":"poolA:3333","user":"acct","max_rental_secs":3600}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(set).await.unwrap().status(),
            StatusCode::OK
        );

        // 5h rental on a 1h-capped rig → rejected as too long (before the
        // offline check, so no connected miner needed).
        let until = now_ms() + 5 * 3600 * 1000;
        let post = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(format!(
                r#"{{"worker":"bc1qSELLER.rig1","url":"buyer:3333","user":"b","until_ms":{until}}}"#
            )))
            .unwrap();
        let resp = app.clone().oneshot(post).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("too long"));

        // Open-ended (until_ms=0) on a capped rig → rejected (needs an end time).
        let post2 = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(
                r#"{"worker":"bc1qSELLER.rig1","url":"buyer:3333","user":"b","until_ms":0}"#,
            ))
            .unwrap();
        let resp2 = app.oneshot(post2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::CONFLICT);
        assert!(body_text(resp2).await.contains("set an end time"));
    }

    #[tokio::test]
    async fn create_order_with_past_end_time_is_rejected() {
        // A bounded rental whose end time is already in the past is rejected
        // before any rig/offline checks (it would otherwise create a dead order).
        let app = app().await;
        let until = now_ms() - 1000; // in the past
        let post = Request::post("/api/orders")
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(format!(
                r#"{{"worker":"bc1qSELLER.rig1","url":"buyer:3333","user":"b","until_ms":{until}}}"#
            )))
            .unwrap();
        let resp = app.oneshot(post).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("future"));
    }

    fn put_pools(id: &str, body: String) -> Request<Body> {
        Request::put(format!("/api/orders/{id}/pools"))
            .header("content-type", "application/json")
            .header("authorization", BEARER)
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn a_running_orders_pools_are_replaced_after_a_probe() {
        use crate::probe::tests::{sv1_pool, Sv1Pool};
        let (app, orders) = app_with_orders().await;
        let order = orders
            .create("bc1qA.rig1".to_string(), buyer_target(), None, 0, 2.0, 9.0)
            .await
            .unwrap();
        let live = sv1_pool(Sv1Pool::Job {
            height: 2,
            prev: [0; 32],
        })
        .await;
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().to_string()
        };

        // A pool that does not answer is refused and the order keeps its pools.
        let body = format!(r#"{{"url":"{dead}","user":"b2"}}"#);
        let resp = app
            .clone()
            .oneshot(put_pools(&order.id, body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "pool-unreachable");
        assert_eq!(v["pool"], "primary");
        assert_eq!(orders.get(&order.id).await.unwrap().target, buyer_target());

        // A failing fallback refuses the change as a whole.
        let body = format!(
            r#"{{"url":"{}","user":"b2","fallback_url":"{dead}","fallback_user":"b3"}}"#,
            live.url
        );
        let resp = app
            .clone()
            .oneshot(put_pools(&order.id, body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body_json(resp).await["pool"], "fallback");
        assert_eq!(orders.get(&order.id).await.unwrap().target, buyer_target());

        // A pool that takes the rig's login replaces the order's.
        let body = format!(
            r#"{{"url":"stratum+tcp://{}","user":"b2","pass":"p"}}"#,
            live.url
        );
        let resp = app
            .clone()
            .oneshot(put_pools(&order.id, body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["order"]["id"], order.id.as_str());
        assert_eq!(v["order"]["target"]["url"], live.url.as_str());
        assert_eq!(v["order"]["budget"], 9.0);
        assert_eq!(v["reconnected"], 0, "no miner is connected");
        let stored = orders.get(&order.id).await.unwrap();
        assert_eq!(stored.target.url, live.url);
        assert_eq!(stored.target.user, "b2");
        assert_eq!(stored.target.password, "p");
        assert_eq!(stored.fallback, None);
    }

    #[tokio::test]
    async fn an_orders_pools_are_not_replaced_when_the_request_cannot_apply() {
        let (app, orders) = app_with_orders().await;
        let order = orders
            .create("bc1qA.rig1".to_string(), buyer_target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();
        let body = || r#"{"url":"other:3333","user":"b2"}"#.to_string();

        let resp = app
            .clone()
            .oneshot(put_pools("o0-0", body()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let bad = r#"{"url":"stratum+ssl://other:3333","user":"b2"}"#.to_string();
        let resp = app
            .clone()
            .oneshot(put_pools(&order.id, bad))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // The pools it already has: nothing to probe, nothing to move. The
        // pool does not exist, so a probe would have refused it.
        let same = r#"{"url":"buyer:3333","user":"b","pass":"x"}"#.to_string();
        let resp = app
            .clone()
            .oneshot(put_pools(&order.id, same))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["reconnected"], 0);

        orders.cancel(&order.id).await.unwrap();
        let resp = app
            .clone()
            .oneshot(put_pools(&order.id, body()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("not active"));
        assert_eq!(orders.get(&order.id).await.unwrap().target, buyer_target());
    }

    #[tokio::test]
    async fn a_rented_rig_is_neither_edited_nor_deleted_until_the_order_ends() {
        let (app, orders) = app_with_orders().await;
        put_rig(&app, "bc1qA.rig1").await;
        let order = orders
            .create("bc1qA.rig1".to_string(), buyer_target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();

        let put = || {
            Request::put("/api/sellers/bc1qA.rig1")
                .header("content-type", "application/json")
                .header("authorization", BEARER)
                .body(Body::from(r#"{"url":"poolB:3333","user":"acct"}"#))
                .unwrap()
        };
        let del = || {
            Request::delete("/api/sellers/bc1qA.rig1")
                .header("authorization", BEARER)
                .body(Body::empty())
                .unwrap()
        };
        let resp = app.clone().oneshot(put()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(body_text(resp).await.contains("rented"));
        let resp = app.clone().oneshot(del()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        orders.cancel(&order.id).await;
        assert_eq!(
            app.clone().oneshot(put()).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(app.oneshot(del()).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_order_for_already_rented_worker_is_rejected() {
        // A worker with a live rental can't be rented again, even while online.
        let (app, orders) = app_with_orders().await;
        orders
            .create("bc1qA.rig1".to_string(), buyer_target(), None, 0, 0.0, 0.0)
            .await
            .unwrap();

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
            Rig {
                advertised_ths: 100.0,
                ..Default::default()
            },
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
        assert_eq!(
            app.clone().oneshot(off).await.unwrap().status(),
            StatusCode::OK
        );

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
        assert_eq!(
            app.clone().oneshot(on).await.unwrap().status(),
            StatusCode::OK
        );

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
