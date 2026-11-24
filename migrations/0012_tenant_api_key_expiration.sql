ALTER TABLE tenant_api_keys
    ADD COLUMN expires_at timestamptz;

CREATE INDEX tenant_api_keys_expiration_idx
    ON tenant_api_keys(expires_at)
    WHERE active AND expires_at IS NOT NULL;
