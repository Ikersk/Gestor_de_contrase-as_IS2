-- MFA basado en TOTP (RFC 6238) para el login.
-- El secreto se guarda cifrado con AES-256-GCM usando la clave del servidor
-- (TOTP_ENC_KEY); mfa_secret solo contiene base64(iv):base64(ciphertext+tag).
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_secret TEXT;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Anti-replay: ultimo time-step (30s) aceptado; impide reutilizar un codigo valido.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_last_counter BIGINT NOT NULL DEFAULT 0;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_setup_at TIMESTAMPTZ;

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_mfa_last_counter_non_negative;

ALTER TABLE users
  ADD CONSTRAINT users_mfa_last_counter_non_negative CHECK (mfa_last_counter >= 0);

-- Codigos de respaldo de un solo uso para cuando se pierde el dispositivo TOTP.
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,   -- bcrypt(cost 12) del codigo normalizado
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS mfa_backup_codes_user_id_idx
  ON mfa_backup_codes (user_id);

ALTER TABLE mfa_backup_codes ENABLE ROW LEVEL SECURITY;
