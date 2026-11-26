-- Phase 2: more notification channels, permanent responder removal, and team-scoped schedules.
--
-- Deliverable channels (queued in the outbox and sent by the worker): email, webhook, slack, discord.
-- Contact-only channels (stored on the responder, never queued): phone, mobile, whatsapp.

-- Replace the channel CHECK constraints regardless of how earlier migrations named them.
DO $$
DECLARE c record;
BEGIN
    FOR c IN
        SELECT conrelid::regclass::text AS tbl, conname
        FROM pg_constraint
        WHERE contype = 'c'
          AND conrelid IN ('notification_recipients'::regclass, 'notification_outbox'::regclass)
          AND pg_get_constraintdef(oid) ILIKE '%channel%'
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.tbl, c.conname);
    END LOOP;
END $$;

ALTER TABLE notification_recipients
    ADD CONSTRAINT notification_recipients_channel_check
    CHECK (channel IN ('email','webhook','slack','discord','phone','mobile','whatsapp'));

ALTER TABLE notification_outbox
    ADD CONSTRAINT notification_outbox_channel_check
    CHECK (channel IN ('email','webhook','slack','discord'));

-- Permanently removing a responder must not be blocked by (or erase) delivery history.
-- The outbox already stores channel and destination, so the recipient link can be dropped.
ALTER TABLE notification_outbox ALTER COLUMN recipient_id DROP NOT NULL;
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_recipient_id_fkey;
ALTER TABLE notification_outbox
    ADD CONSTRAINT notification_outbox_recipient_id_fkey
    FOREIGN KEY (recipient_id) REFERENCES notification_recipients(id) ON DELETE SET NULL;

-- An on-call schedule can belong to a team; only unassigned members or that team's members may join it.
ALTER TABLE on_call_schedules
    ADD COLUMN team text NOT NULL DEFAULT '' CHECK (length(team) <= 120);
