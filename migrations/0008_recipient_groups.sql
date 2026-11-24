ALTER TABLE notification_recipients
    ADD COLUMN groups text[] NOT NULL DEFAULT '{}';

UPDATE notification_recipients
SET groups = ARRAY[btrim(team)]
WHERE btrim(team) <> '';

CREATE INDEX notification_recipients_groups_gin_idx
    ON notification_recipients USING gin(groups);
