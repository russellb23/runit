CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO tenants(id,name,slug)
VALUES('00000000-0000-4000-8000-000000000001','Default tenant','default')
ON CONFLICT(slug) DO NOTHING;

CREATE TABLE tenant_api_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL DEFAULT 'integration key',
    key_hash text NOT NULL UNIQUE,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX tenant_api_keys_tenant_idx ON tenant_api_keys(tenant_id) WHERE active;

ALTER TABLE incidents ADD COLUMN tenant_id uuid;
ALTER TABLE escalation_policies ADD COLUMN tenant_id uuid;
ALTER TABLE notification_recipients ADD COLUMN tenant_id uuid;
ALTER TABLE incident_escalations ADD COLUMN tenant_id uuid;
ALTER TABLE notification_outbox ADD COLUMN tenant_id uuid;

UPDATE incidents SET tenant_id='00000000-0000-4000-8000-000000000001';
UPDATE escalation_policies SET tenant_id='00000000-0000-4000-8000-000000000001';
UPDATE notification_recipients SET tenant_id='00000000-0000-4000-8000-000000000001';
UPDATE incident_escalations SET tenant_id='00000000-0000-4000-8000-000000000001';
UPDATE notification_outbox SET tenant_id='00000000-0000-4000-8000-000000000001';

ALTER TABLE incidents ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE escalation_policies ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE notification_recipients ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE incident_escalations ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE notification_outbox ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE incidents ADD CONSTRAINT incidents_tenant_fk FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE escalation_policies ADD CONSTRAINT escalation_policies_tenant_fk FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE notification_recipients ADD CONSTRAINT notification_recipients_tenant_fk FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE incident_escalations ADD CONSTRAINT incident_escalations_tenant_fk FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_tenant_fk FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_dedup_key_key;
CREATE UNIQUE INDEX incidents_tenant_dedup_key_idx ON incidents(tenant_id,dedup_key);
CREATE INDEX incidents_tenant_created_idx ON incidents(tenant_id,created_at DESC);
CREATE INDEX escalation_policies_tenant_name_idx ON escalation_policies(tenant_id,name);

ALTER TABLE notification_recipients DROP CONSTRAINT IF EXISTS notification_recipients_handle_channel_key;
CREATE UNIQUE INDEX notification_recipients_tenant_handle_channel_idx ON notification_recipients(tenant_id,handle,channel);
CREATE INDEX notification_recipients_tenant_team_idx ON notification_recipients(tenant_id,team) WHERE active;
CREATE INDEX incident_escalations_tenant_due_idx ON incident_escalations(tenant_id,next_run_at) WHERE status='active';
CREATE INDEX notification_outbox_tenant_due_idx ON notification_outbox(tenant_id,next_attempt_at) WHERE status IN ('pending','sending');
