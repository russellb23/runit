CREATE TABLE incidents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dedup_key text NOT NULL UNIQUE,
    title text NOT NULL,
    description text NOT NULL DEFAULT '',
    severity text NOT NULL CHECK (severity IN ('critical','error','warning','info')),
    status text NOT NULL CHECK (status IN ('triggered','acknowledged','resolved')),
    source text NOT NULL DEFAULT '',
    service text NOT NULL DEFAULT '',
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    assignee text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    resolved_at timestamptz
);
CREATE INDEX incidents_status_created_idx ON incidents(status, created_at DESC);
CREATE INDEX incidents_service_created_idx ON incidents(service, created_at DESC);
CREATE TABLE incident_events (
    id bigserial PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind text NOT NULL,
    actor text NOT NULL,
    note text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_events_incident_created_idx ON incident_events(incident_id, created_at);

