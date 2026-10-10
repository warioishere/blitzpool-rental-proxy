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

**Protocol scope:** Stratum **V1 and V2** are both supported (SV2 over the
Noise-encrypted binary protocol, including Extended and Standard channels). On
top of that the proxy has a **bidirectional SV1↔SV2 translator**: a seller's
miner of *either* protocol can be rented onto a buyer pool of *either*
protocol. All four combinations work — SV1→SV1 and SV2→SV2 passthrough, plus
SV1 miner→SV2 pool and SV2 miner→SV1 pool translation. The core (session,
routing, control, accounting) is protocol-agnostic; SV1, SV2 and the translator
are pluggable transport/codec adapters (`src/proto/`).

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
- **session**: idle (the rig's own pool) or rented (an order's pool), plus a
  rolling share window for per-miner hashrate.
- **control API**: driven by the web UI; register rigs and idle pools,
  start/stop rentals, order history.
- **accounting**: delivered work per order (accepted shares × difficulty),
  the basis for billing (buyers) and payout (sellers).

Protocol handling (`src/proto/`): an SV1 relay and an SV2 relay, each driving
one miner connection with a **swappable upstream**, plus `translate`, which
bridges the two protocols in both directions. SV1 and SV2 miners share one
port; the first byte of each connection decides which relay serves it.

### The one hard problem: switching upstream

A new upstream hands out a different extranonce + difficulty. Every pool
change the miner did not start (idle-pool edit, rent start, rent end, and
recovery after the upstream pool dropped) **forces the miner to reconnect**,
so it re-handshakes cleanly against the new upstream, with the correct
extranonce and difficulty from the first job. A live re-point cannot carry
everything (SV2 has no message for a channel's extranonce *size*), and a miner
that silently ignores one wastes every share.

## Build

```
cargo build --release
```

SQL queries are checked at compile time against the committed `.sqlx/`
cache; set `SQLX_OFFLINE=true` to build without a database.

## References (inspiration, not dependencies)

- `miningmeter/stratum-proxy` (Go) — the per-worker-owns-an-upstream shape +
  per-worker hashrate window.
- `blitzpool-rust` `bp-stratum-v1` / SRI `sv2-apps` — framing/correctness.

## Status

Beta. Deployed and running, but still maturing — expect rough edges.
