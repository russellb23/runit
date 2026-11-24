CREATE TABLE on_call_schedules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    timezone text NOT NULL,
    rotation_interval_minutes integer NOT NULL CHECK (rotation_interval_minutes BETWEEN 15 AND 43200),
    rotation_starts_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE on_call_schedule_members (
    schedule_id uuid NOT NULL REFERENCES on_call_schedules(id) ON DELETE CASCADE,
    position integer NOT NULL CHECK (position >= 0),
    handle text NOT NULL,
    PRIMARY KEY (schedule_id, position),
    UNIQUE (schedule_id, handle)
);

CREATE INDEX on_call_schedules_tenant_idx ON on_call_schedules(tenant_id, name);
