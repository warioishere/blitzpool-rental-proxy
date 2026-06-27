-- Optional fallback pool per order: where the proxy routes the rented hashrate
-- when the buyer's primary pool is unreachable (offline at the switch, or it
-- drops mid-rental). Same protocol as the rented rig (the proxy doesn't
-- translate). NULL fallback_url = no fallback configured.
ALTER TABLE orders ADD COLUMN fallback_url TEXT;
ALTER TABLE orders ADD COLUMN fallback_user TEXT;
ALTER TABLE orders ADD COLUMN fallback_password TEXT;
ALTER TABLE orders ADD COLUMN fallback_authority TEXT;
