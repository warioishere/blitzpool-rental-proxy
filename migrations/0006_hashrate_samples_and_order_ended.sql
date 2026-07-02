-- Per-rig hashrate history + order end timestamp (for the marketplace rig chart).

-- When an order left 'active' (ended or cancelled), epoch ms. 0 = still active,
-- or unknown for rows that ended before this migration (the history endpoint
-- then falls back to until_ms for the rental band's end).
ALTER TABLE orders ADD COLUMN ended_ms INTEGER NOT NULL DEFAULT 0;

-- Per-rig delivered-hashrate samples, one row per 10-minute wall-clock slot
-- (slot_ms = floor(ts_ms / 600000) * 600000). `hashrate_ths` is the slot's
-- delivered hashrate in TH/s — the proxy's live estimate is already a ~10-min
-- rolling average, so a single read per slot is that slot's average.
-- `online` = 1 if the rig was delivering that slot, 0 if offline. The sampler
-- prunes rows older than 7 days.
CREATE TABLE IF NOT EXISTS rig_hashrate_samples (
    worker       TEXT    NOT NULL,
    slot_ms      INTEGER NOT NULL,
    hashrate_ths REAL    NOT NULL,
    online       INTEGER NOT NULL,
    PRIMARY KEY (worker, slot_ms)
);

CREATE INDEX IF NOT EXISTS idx_hashrate_samples_slot ON rig_hashrate_samples (slot_ms);
