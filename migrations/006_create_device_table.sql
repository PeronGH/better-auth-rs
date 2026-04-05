-- Devices table for Device authorization grant type (eg. for cli apps)
CREATE TABLE devices (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       TEXT,
    device_name     TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    refresh_hash    TEXT,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_expires_at ON devices(expires_at);
