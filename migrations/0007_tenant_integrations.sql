CREATE TABLE tenant_integrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_key text NOT NULL,
    name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
    credential_reference text,
    validation_status text NOT NULL DEFAULT 'not_validated',
    last_validated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_integrations_validation_check CHECK (validation_status IN ('not_validated','valid','invalid')),
    CONSTRAINT tenant_integrations_name_check CHECK (length(name) BETWEEN 1 AND 120)
);

CREATE INDEX tenant_integrations_tenant_idx ON tenant_integrations(tenant_id, updated_at DESC);
