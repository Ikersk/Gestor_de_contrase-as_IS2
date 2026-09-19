-- Permite invalidar todas las sesiones emitidas antes de un cambio sensible.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_session_version_non_negative;

ALTER TABLE users
  ADD CONSTRAINT users_session_version_non_negative CHECK (session_version >= 0);