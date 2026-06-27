-- Enforce at most one active order per worker (closes a create-order race where
-- two concurrent rentals could both pass the application-level check and insert
-- two active orders for the same worker).
--
-- Before adding the unique index, end any pre-existing duplicate active orders —
-- keep the most recent per worker (by created_ms, then rowid) — so the index can
-- be built on existing data instead of failing at boot.
UPDATE orders SET status = 'ended'
WHERE status = 'active'
  AND EXISTS (
    SELECT 1 FROM orders newer
    WHERE newer.worker = orders.worker
      AND newer.status = 'active'
      AND (newer.created_ms > orders.created_ms
           OR (newer.created_ms = orders.created_ms AND newer.rowid > orders.rowid))
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_one_active_per_worker
    ON orders (worker) WHERE status = 'active';
