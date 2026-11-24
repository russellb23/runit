ALTER TABLE incidents ADD COLUMN escalation_policy_id uuid REFERENCES escalation_policies(id) ON DELETE SET NULL;

CREATE TABLE notification_recipients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    handle text NOT NULL,
    channel text NOT NULL CHECK (channel IN ('email','webhook')),
    destination text NOT NULL,
    team text NOT NULL DEFAULT '',
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(handle, channel)
);
CREATE INDEX notification_recipients_team_idx ON notification_recipients(team) WHERE active;

CREATE TABLE incident_escalations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id uuid NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    policy_id uuid NOT NULL REFERENCES escalation_policies(id) ON DELETE CASCADE,
    step_index integer NOT NULL DEFAULT 0,
    cycle integer NOT NULL DEFAULT 0,
    next_run_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','cancelled')),
    last_error text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_escalations_due_idx ON incident_escalations(next_run_at) WHERE status='active';

CREATE TABLE notification_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    escalation_run_id uuid NOT NULL REFERENCES incident_escalations(id) ON UPDATE CASCADE ON DELETE CASCADE,
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    cycle integer NOT NULL,
    step_index integer NOT NULL,
    recipient_id uuid NOT NULL REFERENCES notification_recipients(id) ON DELETE RESTRICT,
    channel text NOT NULL CHECK (channel IN ('email','webhook')),
    destination text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','delivered','dead','cancelled')),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 10,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    delivered_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(escalation_run_id, cycle, step_index, recipient_id)
);
CREATE INDEX notification_outbox_due_idx ON notification_outbox(next_attempt_at) WHERE status IN ('pending','sending');

