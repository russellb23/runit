ALTER TABLE tenant_api_keys ADD COLUMN role text NOT NULL DEFAULT 'owner';
ALTER TABLE tenant_api_keys ADD CONSTRAINT tenant_api_keys_role_check CHECK (role IN ('owner','admin','responder','integration','viewer'));
