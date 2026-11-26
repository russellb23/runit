# RelayOps PostgreSQL reference

## How schema changes run

The API applies versioned SQL migrations at startup through `sqlx::migrate!()`. Migration files are append-only and tracked in SQLx's `_sqlx_migrations` table. The current schema is built by `migrations/0001_init.sql` through `migrations/0012_tenant_api_key_expiration.sql`. Production deployments should run migrations once as a release step before updating API replicas; the current Compose stack runs them during API startup.

RelayOps does not create PostgreSQL stored procedures, triggers, or user-defined functions. Database procedures below means the transaction and query flows implemented in Rust with parameterized SQLx queries. PostgreSQL functions used by migrations include `gen_random_uuid()` and `nextval()`.

## Table catalog

### `tenants`

`id uuid` primary key, `name text`, `slug text` unique, `created_at timestamptz`. Migration 0005 seeds the `default` tenant. Every tenant-owned record references a tenant; deleting a tenant cascades to its data and credentials.

### `tenant_api_keys`

`id uuid`, `tenant_id uuid`, `name text`, `key_hash text` unique, `active boolean`, `created_at`, `last_used_at`, `role text`, and nullable `expires_at timestamptz`. Expired keys are rejected by authentication and shown inactive in key metadata. Key roles are `owner`, `admin`, `responder`, `integration`, and `viewer`. Raw secrets are returned once at creation or rotation; only SHA-256 hashes are stored. Owners/admins can set or clear expiration, atomically rotate keys, or revoke them. Admins cannot modify owner/admin keys. The platform `API_KEY` is held in application configuration and is not stored in this table.

### `incidents`

`id uuid`, globally unique numeric `incident_number`, tenant-scoped `dedup_key`, `title`, `description`, `severity`, `status`, `source`, `service`, JSONB `labels` and `metadata`, nullable `assignee`, `created_at`, `updated_at`, nullable `acknowledged_at` and `resolved_at`, `tenant_id`, and nullable `escalation_policy_id`. Severity is constrained to `critical`, `error`, `warning`, or `info`; status is `triggered`, `acknowledged`, or `resolved`. `(tenant_id,dedup_key)` is unique. Human IDs are formatted `RLY-########` by API responses.

### `incident_events`

Append-style event history: `id bigserial`, `incident_id`, `kind`, `actor`, `note`, and `created_at`. Events cascade with their incident. The incident event endpoint joins through the incident's tenant before returning data.

### `escalation_policies`

`id uuid`, `tenant_id`, `name`, `description`, IANA `timezone`, `repeat_count`, `repeat_every_minutes`, JSONB `steps`, `created_at`, `updated_at`. Steps contain `delay_minutes`, `target_type` (`user`, `team`, `schedule`, `channel`), and `target`. Constraints cap repeat count at 20 and step count at 10. `timezone` is policy metadata; step delays are elapsed minutes.

### `notification_recipients`

One channel destination per `(tenant_id,handle,channel)`: `id`, `tenant_id`, `handle`, `channel`, `destination`, `team`, `groups text[]`, `active`, `created_at`, `updated_at`. Channels are `email`, `webhook`, `slack`, `discord`, `phone`, `mobile`, and `whatsapp`. The worker delivers `email`, `webhook`, `slack` (incoming-webhook URL), and `discord` (webhook URL); `phone`, `mobile`, and `whatsapp` are stored contact details only and are never queued. Phone-style destinations are normalised to `+<digits>`. Group membership is indexed with a GIN index. Schedules reference the stable `handle`, not a specific channel row.

### `incident_escalations`

Durable escalation run state: `id`, `tenant_id`, unique `incident_id`, `policy_id`, `step_index`, `cycle`, `next_run_at`, `status` (`active`, `completed`, `cancelled`), `last_error`, and `updated_at`. A due-time partial index supports worker polling. Acknowledging or resolving an incident cancels its active run.

### `notification_outbox`

Durable delivery jobs: `id`, `escalation_run_id`, `tenant_id`, `incident_id`, `cycle`, `step_index`, `recipient_id`, `channel`, `destination`, JSONB `payload`, `status` (`pending`, `sending`, `delivered`, `dead`, `cancelled`), `attempts`, `max_attempts`, `next_attempt_at`, nullable `locked_at` and `delivered_at`, `last_error`, and `created_at`. `(escalation_run_id,cycle,step_index,recipient_id)` is unique to avoid duplicate queue rows for one escalation step. `recipient_id` is nullable and `ON DELETE SET NULL`, so permanently removing a responder keeps their delivery history (channel and destination are stored on the job). Outbox channels are limited to `email`, `webhook`, `slack`, and `discord`.

### `tenant_integrations`

Connector configuration: `id`, `tenant_id`, `connector_key`, `name`, `enabled`, JSONB `configuration`, nullable `credential_reference`, `validation_status`, nullable `last_validated_at`, `created_at`, and `updated_at`. Credentials must remain in a secret manager; the API rejects secret-like keys in `configuration`. Validation currently checks configuration shape and adapter availability, not a live provider connection.

### `tenant_users` and `user_sessions`

`tenant_users` stores `id`, `tenant_id`, lower-case-unique-per-tenant `email`, `display_name`, Argon2id `password_hash`, role (`owner`, `admin`, `responder`, `viewer`), `is_product_owner`, `active`, failed login count, lock expiry, and timestamps. Startup creates the configured product-owner account in the default tenant. On the first promotion of a regular account matching `PRODUCT_OWNER_EMAIL`, it applies `PRODUCT_OWNER_PASSWORD` once and clears its failed-login lock; later restarts preserve password changes. `user_sessions` stores the tenant/user IDs, unique SHA-256 `token_hash`, created/last-seen/expiry/revocation times, and user-agent text. Raw session tokens exist only in the HttpOnly cookie. Session expiry is 12 hours.

### `notification_team_leads`, `incident_assignment_requests`, and `incident_spikes`

`notification_team_leads` holds at most one lead per `(tenant_id,team)`; `handle` is a responder handle and the lead must be an active member of that team or group. `incident_assignment_requests` records a request from someone who is not the assignee's team lead (`requested_by`, `assignee`, `note`, `status` of `pending`, `accepted`, or `declined`); one pending request is allowed per `(incident_id,assignee)`. `incident_spikes` records a mistaken-assignment flag from the current assignee to their team lead (`raised_by`, `team_lead`, `reason`, `status` of `open`, `reassigned`, or `dismissed`, `resolution_note`); one spike can be open per incident. Assignment, request, spike, and demo activity is also written to `incident_events` (`assigned`, `assignment_requested`, `assignment_accepted`, `assignment_declined`, `spike_raised`, `spike_dismissed`, `demo_started`, `demo_notification_simulated`).

### `on_call_schedules` and `on_call_schedule_members`

`on_call_schedules` stores `id`, `tenant_id`, unique-per-tenant `name`, IANA `timezone`, `rotation_interval_minutes` (15–43200), `rotation_starts_at timestamptz`, `team text` (empty by default; when set, members must belong to that team/group or to no team at all), and timestamps. `on_call_schedule_members` stores an ordered list of unique responder handles per schedule. Every member must have at least one active deliverable channel (`email`, `webhook`, `slack`, or `discord`) at create/update time; contact-only channels do not count. The worker rotates by elapsed intervals from the start instant; the timezone is used for display and does not change the elapsed-minute rotation cadence. Use a schedule's name as an escalation step's `target` when `target_type` is `schedule`.

## Runtime SQL procedures

### Authenticate a request

The middleware hashes bearer API keys and looks up only active keys, updating `last_used_at`. The platform key maps to the default tenant and owner role. Browser cookies are hashed and matched to an unexpired, non-revoked session joined to an active user. The middleware injects tenant, role, and product-owner context; only a platform key or the seeded product-owner login can perform cross-tenant administration. Handlers bind tenant IDs into tenant-owned reads and writes.

### Ingest, group, and reopen incidents

`POST /v1/alerts` inserts an incident with initial status `triggered`, using `ON CONFLICT (tenant_id,dedup_key)` to refresh the existing record. A resolved record is reopened and its `resolved_at` is cleared. When an escalation policy is included, the run is created or restarted if its previous state is completed/cancelled. The unique tenant/dedup index provides the concurrency boundary.

### Acknowledge or resolve

The incident update, event insert, and escalation cancellation run in one SQL transaction. Acknowledgement updates the assignee and acknowledgment time; resolution sets the resolution time. The worker later sees the non-triggered status and cancels queued sends that have not yet been delivered.

### Process due escalation steps

Every API process runs a worker loop every two seconds. A transaction selects up to 25 due active runs ordered by `next_run_at` using `FOR UPDATE SKIP LOCKED`, which lets replicas share work. The worker verifies the incident is still triggered, reads the tenant policy and step JSON, resolves user/team/schedule/channel targets, inserts outbox rows, appends an `escalation_queued` event, advances `step_index` or repeat `cycle`, and commits. Missing active recipients cause target resolution to retry in one minute.

For a `schedule` step, target resolution reads the schedule by UUID or name, loads ordered handles, and selects the current slot as `floor((now - rotation_starts_at) / rotation_interval) mod member_count`. All active channels for that one handle are queued. If the anchor is in the future or the schedule/handle cannot resolve, the run retries target lookup.

### Deliver, retry, and recover queue leases

The worker first returns `sending` rows with leases older than ten minutes to `pending`. It claims up to five due pending jobs in a single `UPDATE ... FROM (SELECT ... FOR UPDATE SKIP LOCKED)` query, marks them `sending`, and increments attempts. Successful jobs become `delivered`; jobs for acknowledged/resolved incidents become `cancelled`. Failure schedules exponential backoff starting at 30 seconds, capped at one hour, and marks a job `dead` after `max_attempts` (default 10). The retry API resets dead jobs to pending.

### Create or replace an on-call schedule

Schedule create/update validates the IANA timezone, interval bounds, unique ordered handles, and that every handle has an active deliverable channel in the same tenant. The schedule row and its ordered member rows are written in a transaction. Updating replaces all member rows atomically; deleting a schedule cascades its member rows.

## Migration index

| Migration | Change |
| --- | --- |
| `0001_init.sql` | Incidents and event history |
| `0002_escalation_policies.sql` | Escalation policies and JSON step state |
| `0003_escalation_delivery.sql` | Notification recipients, escalation runs, durable outbox |
| `0004_incident_numbers.sql` | Human-readable incident number sequence |
| `0005_tenants.sql` | Tenants, API keys, tenant scoping and tenant indexes |
| `0006_api_key_roles.sql` | API key role checks |
| `0007_tenant_integrations.sql` | Per-tenant connector configuration |
| `0008_recipient_groups.sql` | Responder group memberships |
| `0009_login_sessions.sql` | Login accounts and hashed browser sessions |
| `0010_on_call_schedules.sql` | Timezone-labelled on-call rotations and ordered members |
| `0011_product_owner.sql` | Product-owner identity flag for platform tenant administration |
| `0012_tenant_api_key_expiration.sql` | Optional expiration timestamps on tenant API keys |
| `0013_channels_removal_schedule_team.sql` | Slack, Discord, phone, mobile, and WhatsApp channels; nullable outbox `recipient_id` for responder removal; schedule `team` |
| `0014_relay_assignment_spikes.sql` | Team leads, assignment requests, and spikes on mistaken assignments |
