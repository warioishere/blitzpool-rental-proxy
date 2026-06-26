# stratum-rental-proxy

A Stratum **hashrate-rental** proxy.

A seller registers a miner. While **idle**, the miner mines on the seller's
**own default pool**. When a buyer **rents** it, the proxy reroutes that
miner's hashrate **server-side** to the buyer's chosen target (pool + worker)
for the rental duration, then switches it back to the default — the seller
never reconfigures the miner.

This is the inverse of a mining pool: a pool *generates* its own block
templates; this proxy *forwards* a miner's work to an upstream of someone
else's choosing and measures the delivered hashrate for billing/payout.

**Protocol scope:** Stratum **V1 first**, Stratum **V2 planned**. The core
(session, routing, control, accounting) is protocol-agnostic; SV1 and SV2 are
pluggable transport/codec adapters (`src/proto/`).

## Why a proxy, not a pool

When a miner is rented out, the shares/blocks it finds are submitted to the
**buyer's** upstream and credit the **buyer**. The seller earns a **rental
fee**, not the mining reward. The proxy measures hashrate at the wire (share
rate × difficulty) to know how much each seller delivered (→ payout) and how
much each buyer received (→ billing). The operator takes a margin.

## Architecture

```
seller miners ──▶  [ this proxy ]  ──▶  upstream pool
                    per-session:        (default pool when idle,
                     downstream conn     buyer target when rented)
                     + SWAPPABLE upstream
                     + share window (hashrate)
                    control API  ◀── web UI (orders, pool switch, config)
```

Protocol-agnostic core:
- **session** — `Idle(default_pool)` | `Rented(target, until)` + a rolling
  share window for per-miner hashrate.
- **router / control API** — driven by the web UI: register sellers + default
  pools, start/stop rentals (the pool switch), buyer orders, configuration.
- **accounting** — delivered hashrate per seller → billing (buyers) + payout
  (sellers).

Pluggable protocol adapters (`src/proto/`):
- **downstream** — Stratum server: accept seller miners.
- **upstream** — Stratum client: one connection per session, **swappable at
  runtime**.
- `sv1` now; `sv2` later (same session/router/accounting underneath).

### The one hard problem: switching upstream mid-session

A new upstream hands out a different extranonce + difficulty. To switch
without dropping the miner:
- **SV1:** if the miner negotiated `mining.extranonce.subscribe`, push
  `mining.set_extranonce` + `mining.set_difficulty` + `mining.notify(clean)`;
  otherwise fall back to `client.reconnect`.
- **SV2 (later):** the channel/`SetExtranoncePrefix` + `SetTarget` machinery
  makes this cleaner natively.

## Milestones

1. **Core pass-through (SV1)** — accept a miner, connect to one (default)
   upstream, relay subscribe/authorize/notify/set_difficulty/submit, measure
   per-miner hashrate. *(in progress)*
2. **Switch (SV1)** — swap the upstream at runtime + extranonce handling +
   control API (`set_target` / `clear_target`).
3. **Rental layer** — buyer orders, allocation, auto-revert at order end,
   accounting, web UI, seller/buyer configuration.
4. **SV2 adapter** — second protocol adapter under the same core.

## References (inspiration, not dependencies)

- `miningmeter/stratum-proxy` (Go) — the per-worker-owns-an-upstream shape +
  per-worker hashrate window.
- `blitzpool-rust` `bp-stratum-v1` / SRI `sv2-apps` — framing/correctness.

## Status

Early scaffolding. Not production-ready.
