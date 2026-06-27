-- Rigs: a seller's registered rig — idle/default pool + marketplace listing.
CREATE TABLE IF NOT EXISTS rigs (
    worker               TEXT PRIMARY KEY NOT NULL,
    pool_url             TEXT NOT NULL,
    pool_user            TEXT NOT NULL,
    pool_password        TEXT NOT NULL DEFAULT '',
    pool_authority       TEXT,                       -- SV2 Noise authority pubkey (base58), nullable
    advertised_ths       REAL NOT NULL DEFAULT 0,
    price_per_th_day     REAL NOT NULL DEFAULT 0,
    price_min_per_th_day REAL NOT NULL DEFAULT 0,
    price_max_per_th_day REAL NOT NULL DEFAULT 0,
    payout_address       TEXT                        -- seller BTC/LN payout, nullable
);

-- Orders: a buyer renting a worker until a deadline and/or a prepaid budget.
CREATE TABLE IF NOT EXISTS orders (
    id                TEXT PRIMARY KEY NOT NULL,
    worker            TEXT NOT NULL,
    target_url        TEXT NOT NULL,
    target_user       TEXT NOT NULL,
    target_password   TEXT NOT NULL DEFAULT '',
    target_authority  TEXT,
    created_ms        INTEGER NOT NULL,
    until_ms          INTEGER NOT NULL DEFAULT 0,    -- 0 = open-ended
    status            TEXT NOT NULL,                 -- 'active' | 'ended' | 'cancelled'
    delivered_work    REAL NOT NULL DEFAULT 0,       -- diff-1 share units (billing basis)
    accepted_shares   INTEGER NOT NULL DEFAULT 0,
    submitted_shares  INTEGER NOT NULL DEFAULT 0,
    price_per_th_day  REAL NOT NULL DEFAULT 0,
    budget            REAL NOT NULL DEFAULT 0        -- 0 = no limit
);

CREATE INDEX IF NOT EXISTS idx_orders_worker ON orders (worker);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);
