ALTER TABLE tenant_users
    ADD COLUMN is_product_owner boolean NOT NULL DEFAULT false;

CREATE INDEX tenant_users_product_owner_idx
    ON tenant_users(tenant_id, is_product_owner)
    WHERE is_product_owner;
