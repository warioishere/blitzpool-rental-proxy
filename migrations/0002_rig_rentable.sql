-- Whether a registered rig is currently listed for rent in the marketplace.
-- A rig is always served by the proxy (idle-mines on its own pool) once
-- registered; `rentable` only controls marketplace listing + whether a new
-- rental can be created against it. Default 1 = listed (existing rigs stay
-- rentable after this migration).
ALTER TABLE rigs ADD COLUMN rentable INTEGER NOT NULL DEFAULT 1;
