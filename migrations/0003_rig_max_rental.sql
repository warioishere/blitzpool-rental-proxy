-- Optional cap on how long a single rental of this rig may last (seconds).
-- 0 = no cap (open-ended rentals allowed). Set by the seller when registering
-- the rig; enforced at order creation — a buyer's requested duration may not
-- exceed it, and when a cap is set an open-ended rental is rejected. Existing
-- rigs default to 0 (no cap) after this migration.
ALTER TABLE rigs ADD COLUMN max_rental_secs INTEGER NOT NULL DEFAULT 0;
