-- Why an order left 'active', and the pool's own words where there are any.
-- end_reason: deadline | budget | cancelled | pool-rejects-shares |
-- pool-connection-unstable. NULL while active, and for rows that ended before
-- this migration.
ALTER TABLE orders ADD COLUMN end_reason TEXT;
ALTER TABLE orders ADD COLUMN end_detail TEXT;
