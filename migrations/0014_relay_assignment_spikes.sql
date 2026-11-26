-- Phase 3: team leads, assignment requests, and spikes raised on mistakenly assigned relays.

-- One team lead per team/group within a tenant. `handle` is a responder handle.
CREATE TABLE notification_team_leads (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    team text NOT NULL CHECK (length(btrim(team)) > 0),
    handle text NOT NULL CHECK (length(btrim(handle)) > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, team)
);
CREATE INDEX notification_team_leads_handle_idx ON notification_team_leads(tenant_id, handle);

-- A non-lead who assigns a relay to someone else creates a request the assignee must accept or decline.
CREATE TABLE incident_assignment_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    requested_by text NOT NULL,
    assignee text NOT NULL,
    note text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','declined')),
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz
);
CREATE UNIQUE INDEX incident_assignment_requests_pending_idx
    ON incident_assignment_requests(incident_id, assignee) WHERE status = 'pending';
CREATE INDEX incident_assignment_requests_assignee_idx
    ON incident_assignment_requests(tenant_id, assignee) WHERE status = 'pending';

-- An assignee who received a relay by mistake raises a spike to their team lead.
CREATE TABLE incident_spikes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    raised_by text NOT NULL,
    team_lead text NOT NULL,
    reason text NOT NULL CHECK (length(btrim(reason)) > 0),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','reassigned','dismissed')),
    resolution_note text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);
CREATE UNIQUE INDEX incident_spikes_open_idx ON incident_spikes(incident_id) WHERE status = 'open';
CREATE INDEX incident_spikes_lead_idx ON incident_spikes(tenant_id, team_lead) WHERE status = 'open';
