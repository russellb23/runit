CREATE TABLE escalation_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(trim(name)) > 0),
    description text NOT NULL DEFAULT '',
    timezone text NOT NULL DEFAULT 'UTC',
    repeat_count integer NOT NULL DEFAULT 0 CHECK (repeat_count BETWEEN 0 AND 20),
    repeat_every_minutes integer NOT NULL DEFAULT 30 CHECK (repeat_every_minutes BETWEEN 1 AND 10080),
    steps jsonb NOT NULL CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) BETWEEN 1 AND 10),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX escalation_policies_name_idx ON escalation_policies(name);
