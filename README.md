# RelayOps

RelayOps is a self-hosted incident management application with a Next.js operator UI and a Rust API and authentication middleware. It accepts alerts from monitoring systems, groups repeated alerts by a stable deduplication key, and exposes incident acknowledgement, resolution, and event history. Each incident receives a globally unique, human-readable `RLY-########` number alongside its internal UUID; the number appears in the dashboard and notifications. Tenant data is isolated by tenant-scoped API keys and database filters. It is a deployable foundation rather than a feature-complete replacement.

## Included

- PostgreSQL persistence and schema migrations
- Multi-tenant data scoping with per-tenant API keys, tenant roles, and a platform tenant manager
- Role-based API permissions, browser login accounts, and revocable database-backed sessions
- Manual test-flow form that creates a tagged incident through the real escalation and notification path
- Alert ingestion with deduplication and resolved-incident reopening
- Triggered → acknowledged → resolved lifecycle
- Assignee and actor attribution, notes, event history
- API key authentication and health endpoint
- Docker Compose deployment and Kubernetes deployment outline below
- Responsive Next.js operator UI on port 3000, proxied to the Rust API on port 8080

## Run locally with Docker

1. Copy `.env.example` to `.env`; replace the database password, API key, and default product-owner password before exposing the app outside local development.
2. Run `docker compose up --build -d`.
3. Open `http://localhost:3000/` for the Next.js operator UI. API health is at `http://localhost:8080/healthz`; interactive API documentation is at `http://localhost:8080/docs` and the OpenAPI contract is at `http://localhost:8080/openapi.yaml`.
4. On first startup, RelayOps seeds a product-owner login for tenant slug `default`. Sign in with `PRODUCT_OWNER_EMAIL` and `PRODUCT_OWNER_PASSWORD` from `.env` (defaults: `owner@relayops.local` / `RelayOps-Owner-2026!`). The product owner can create tenants and issue their initial keys. Use **First-time setup** with a tenant owner key to create the first login for an additional tenant. Existing API keys continue to work for automation.

The Next.js dashboard supports incident search and filters, acknowledgement and resolution, manual incident creation, an end-to-end test flow, user and channel setup, escalation policy configuration, delivery inspection, tenant management, login accounts, session revocation, and API key administration including rotation, revocation, and expiration controls. The shared header search works across screens and matches partial incident keys, internal IDs, and titles. Right-click an incident for quick response actions; product owners can right-click a tenant to manage that tenant's keys. The Account & sessions navigation entry is hidden for product owners. The navigation bar can be placed on the left, right, top, or bottom; change this under **Settings** and the choice is saved in browser preferences. Browser sessions use HttpOnly cookies; API keys continue to authenticate monitoring integrations.

### Login and browser sessions

On first startup, the API creates the configured product-owner account in the `default` tenant. Local defaults are `owner@relayops.local` / `RelayOps-Owner-2026!`, with tenant slug `default`. **Change `PRODUCT_OWNER_PASSWORD` before production use.** On upgrade, if the configured email already belongs to a regular tenant account, its password is reset to the configured bootstrap password once as it is promoted to product owner. Later restarts preserve password changes. If the account is already a product owner, use **Recover access** with the `API_KEY` value to reset it. A product-owner login can create tenants and issue their first keys. For other tenants, use **First-time setup** with that tenant's owner API key. Tenant admins and owners can add login accounts under **Account & sessions**. Passwords are stored as Argon2id hashes, require at least 12 characters, and five consecutive failed attempts lock that account for 15 minutes. Sessions expire after 12 hours, are stored as token hashes in PostgreSQL, and can be inspected or revoked per account. Set `SESSION_COOKIE_SECURE=true` when serving the app over HTTPS in production; it is `false` in the local Docker example so localhost HTTP works.

The **Tenants** navigation option is visible only to owner-level accounts. Tenant owners see their own tenant; the product-owner login or platform API key can list and create tenants across the platform.

Escalation policies, on-call rotations, and responder channels are stored in PostgreSQL and are available through the Rust API. A PostgreSQL-backed worker evaluates due steps, queues email and signed webhook notifications in a durable outbox, retries failures with exponential delay, and stops a run when the incident is acknowledged or resolved. A schedule escalation step notifies every active channel for the one responder currently on rotation; team steps notify all active matching members.

### Configure and run escalations

1. The default `.env.example` sends mail to the bundled local Mailpit service at `smtp://mailpit:1025`. Copy it to `.env`; messages are captured for testing and do not go to real recipients. Open `http://localhost:8026` to inspect them. The host port is controlled by `MAILPIT_WEB_PORT` (default `8026`); change it if that port is also occupied. The Mailpit inbox is persisted in the `mailpit-data` volume. For real delivery, replace `SMTP_URL` and `SMTP_FROM` with your mail provider settings and secure those values as deployment secrets. Set a random `WEBHOOK_SIGNING_SECRET` of at least 32 characters. Webhook targets require HTTPS.
2. Start or rebuild with `docker compose up --build -d`. Startup applies the database migration, starts the queue worker, and launches Mailpit.
3. Configure responder channels through the `/v1/notification-users` API. Contacts are stored in PostgreSQL. Keep SMTP and webhook signing credentials in deployment secrets.
4. Create on-call rotations from **On-call schedules**. Choose an IANA timezone, anchor date/time, interval, and ordered responder handles. The timezone is used when displaying schedule times; the interval rotates from the saved UTC anchor. Every member must have an active channel.
5. Create escalation policies through `/v1/escalation-policies`. A `user` target matches a responder handle; `team` matches a team or group and notifies all active members; `schedule` targets an on-call schedule by name and notifies the current rotation member; `channel` targets a responder destination. Use the policy timezone to label the policy; step delays are elapsed minutes.
6. When creating an alert, choose its escalation policy. API integrations can instead send `"escalation_policy_id":"<policy UUID>"` in `POST /v1/alerts`.
7. To exercise the full information path manually, select **Run test flow**, fill in the fields, choose a policy, and submit. It creates a clearly labeled incident with a unique test deduplication key and starts the real escalation worker. The selected policy can send actual email and signed webhook messages to matching recipients, so use test destinations first.

### Incident analysis

The **Analysis** navigation page calls `GET /v1/analytics/incidents` for tenant-scoped totals grouped by alert source (the integration/source label) and current assignee. It samples the total incident count every 10 seconds while the page is open and plots the latest 60 samples (up to 10 minutes). Source and assignee counts come from the existing incident records; manual incidents are counted under their submitted source, usually `manual`.
### Integration catalog and tenant configuration

The dashboard's **Integrations** page loads a connector catalog and tenant-owned records from PostgreSQL. Owners and admins can create, edit, validate configuration fields, enable/disable, and remove integration records. Configuration is tenant-scoped in `tenant_integrations`; credentials should be stored in a secret manager and only a reference such as `vault://team/path` is saved. The API rejects configuration properties that appear to contain raw secrets.

- `GET /v1/integration-catalog` lists connector definitions and configuration fields.
- `GET /v1/integrations` lists the authenticated tenant's records.
- `POST /v1/integrations` and `PUT /v1/integrations/{uuid}` create or update a record.
- `POST /v1/integrations/{uuid}/validate` validates stored fields and marks the record valid; this is configuration validation and does not contact the provider.
- `DELETE /v1/integrations/{uuid}` removes a record.

Integration configuration also supports up to 50 custom payload field definitions per connector. Each definition stores a dot-separated payload path, data type, required flag, and description in the tenant integration JSON configuration. These definitions document the expected schema; a connector adapter must consume them to validate or transform live payloads.

The catalog currently includes Alert API, SMTP email, signed HTTPS webhooks, Prometheus Alertmanager, Grafana, Datadog, New Relic, AWS CloudWatch, Google Cloud Monitoring, Azure Monitor, Slack, Microsoft Teams, Jira, and ServiceNow. Only the existing Alert API, SMTP email, and signed webhook flows have runtime adapters. The remaining entries support configuration storage only; installing a record does not enable provider delivery or alert ingestion.
### Multiple tenants

The `API_KEY` in the server environment is the platform bootstrap key and continues to address the `default` tenant for backward compatibility. Use the platform-only `/v1/tenants` API to create tenant records and issue tenant-specific API keys. The key is shown once; store it in your secret manager. Connect the dashboard with the tenant-specific key from its Settings panel. The platform key is required to list tenants or rotate a tenant key; rotation disables that tenant's previous keys. Incidents, deduplication keys, users/channels, policies, escalation runs, and delivery records are tenant-scoped. Existing data is migrated to the `default` tenant.

Notification responders can belong to multiple teams/groups. The Users & channels form lets admins select existing groups or add a new one, and escalation policy steps let them choose a responder, channel, team, or group directly. Memberships are persisted in `notification_recipients.groups`; existing `team` values are migrated as memberships, so team and schedule targets continue to resolve.

### Roles and permissions

Open **Access & roles** in the Next.js UI to issue tenant API keys. The raw secret is shown only once; only its SHA-256 hash is stored. Owners can grant every role. Admins can create responder, integration, and viewer keys and manage ordinary tenant configuration, but cannot grant, rotate, change expiration, or revoke owner/admin keys. Keys can be created with an optional expiration, updated or cleared later, atomically rotated while retaining their role and expiration, or revoked. Expired keys are rejected immediately. The last usable owner key cannot be revoked.

- **Owner:** full tenant access and API key administration.
- **Admin:** manage escalation policies, responders/channels, delivery retries, and lower-privilege keys.
- **Responder:** create incidents, acknowledge and resolve incidents, and read incidents and policies.
- **Integration:** ingest alerts and read incidents and policies.
- **Viewer:** read incidents, event history, and policies.

Tenant records and platform key rotation remain restricted to the environment's platform `API_KEY`.

The first step runs immediately. Later step delays are elapsed minutes from the previous step. Acknowledging or resolving an incident cancels remaining escalation steps and queued notifications. The worker leases jobs using PostgreSQL `SKIP LOCKED`, retries failures up to 10 times with exponential backoff (30 seconds up to one hour), and leaves exhausted jobs in the dead-letter state. `GET /v1/notification-deliveries` lists recent jobs; `POST /v1/notification-deliveries/{uuid}/retry` requeues a dead job. Outbox delivery is at-least-once: a receiver should deduplicate using the incident ID and step/cycle data in the payload.

Webhook receivers get JSON with `X-RelayOps-Timestamp` and `X-RelayOps-Signature: sha256=…`. The signature is HMAC-SHA256 over `<timestamp>.<raw request body>` using `WEBHOOK_SIGNING_SECRET`. Verify signatures with a constant-time comparison and reject stale timestamps.

Authenticated `/v1` calls accept `Authorization: Bearer <API_KEY>` or the browser's `relayops_session` cookie. `POST /v1/auth/login` is public; first-time setup and password recovery require an owner API key. Example:

```sh
curl -X POST http://localhost:8080/v1/alerts \
  -H 'Authorization: Bearer replace-with-at-least-24-random-characters' \
  -H 'Content-Type: application/json' \
  -d '{"dedup_key":"payments/db-latency","title":"Database latency elevated","severity":"critical","source":"prometheus","service":"payments","description":"p99 above 2s"}'
```

The response contains an `incident.id`. Use it with:

```sh
curl -H 'Authorization: Bearer <API_KEY>' http://localhost:8080/v1/incidents
curl -X POST -H 'Authorization: Bearer <API_KEY>' -H 'Content-Type: application/json' \
  -d '{"actor":"oncall@example.com","note":"Investigating"}' \
  http://localhost:8080/v1/incidents/<UUID>/acknowledge
curl -X POST -H 'Authorization: Bearer <API_KEY>' -H 'Content-Type: application/json' \
  -d '{"actor":"oncall@example.com","note":"Mitigated"}' \
  http://localhost:8080/v1/incidents/<UUID>/resolve
curl -H 'Authorization: Bearer <API_KEY>' http://localhost:8080/v1/incidents/<UUID>/events
```

Valid severities: `critical`, `error`, `warning`, `info`. Repeated firing alerts sharing a `dedup_key` update the same incident. A new alert with a resolved key reopens it.

## API

The full API contract is published as OpenAPI 3 at `/openapi.yaml`; browse and try operations in Swagger UI at `/docs`. Request schemas, role requirements, status codes, authentication types, and current paging limits are documented in the specification. PostgreSQL tables, migration history, tenant constraints, and the runtime SQL transaction/worker procedures are described in [`docs/database.md`](docs/database.md).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | Liveness check |
| POST | `/v1/alerts` | Ingest/deduplicate an alert |
| GET | `/v1/incidents` | List latest 500 incidents; optional `search` query partially matches incident key, UUID, or title |
| GET | `/v1/analytics/incidents` | Read tenant incident totals by source and assignee |
| GET | `/v1/incidents/{uuid}` | Fetch one incident |
| POST | `/v1/incidents/{uuid}/acknowledge` | Acknowledge and optionally assign |
| POST | `/v1/incidents/{uuid}/resolve` | Resolve an incident |
| GET | `/v1/incidents/{uuid}/events` | Read its audit events |
| GET | `/v1/escalation-policies` | List escalation policies from PostgreSQL |
| POST | `/v1/escalation-policies` | Create an escalation policy |
| PUT | `/v1/escalation-policies/{uuid}` | Update a policy |
| DELETE | `/v1/escalation-policies/{uuid}` | Delete a policy |
| GET | `/v1/schedules` | List on-call rotations |
| POST | `/v1/schedules` | Create a timezone-labelled on-call rotation |
| PUT | `/v1/schedules/{uuid}` | Replace schedule rotation and member order |
| DELETE | `/v1/schedules/{uuid}` | Delete an on-call schedule |
| GET | `/v1/notification-recipients` | List delivery targets |
| POST | `/v1/notification-recipients` | Create an email or webhook target |
| PUT | `/v1/notification-recipients/{uuid}` | Update a target |
| DELETE | `/v1/notification-recipients/{uuid}` | Deactivate a target |
| GET | `/v1/notification-users` | List responder users and configured channels |
| POST | `/v1/notification-users` | Create a responder and configure channels |
| PUT | `/v1/notification-users/{handle}` | Update a responder's team, group memberships, and channels |
| DELETE | `/v1/notification-users/{handle}` | Pause all of a responder's channels |
| POST | `/v1/auth/login` | Create a tenant browser session from tenant slug, email, and password |
| POST | `/v1/auth/setup` | Create the tenant's first owner login using an owner API key |
| POST | `/v1/auth/recover` | Reset an account password with a tenant owner API key and revoke its sessions |
| GET | `/v1/auth/sessions` | List the signed-in user's active sessions |
| DELETE | `/v1/auth/sessions/{uuid}` | Revoke one of the signed-in user's sessions |
| POST | `/v1/auth/logout` | Revoke the current browser session |
| GET | `/v1/integration-catalog` | List available connector definitions |
| GET | `/v1/integrations` | List configured integrations |
| POST | `/v1/integrations` | Add an integration configuration |
| PUT | `/v1/integrations/{uuid}` | Update an integration configuration |
| DELETE | `/v1/integrations/{uuid}` | Delete an integration configuration |
| POST | `/v1/integrations/{uuid}/validate` | Validate configuration shape and adapter availability |
| GET | `/v1/notification-deliveries` | Inspect queued, delivered, retrying, or dead jobs |
| POST | `/v1/notification-deliveries/{uuid}/retry` | Retry a dead delivery |
| GET | `/v1/tenant` | Read current tenant and API key role |
| GET | `/v1/api-keys` | List tenant API keys (owner/admin) |
| POST | `/v1/api-keys` | Create a role-scoped tenant key (owner/admin) |
| PUT | `/v1/api-keys/{uuid}` | Change or clear a tenant API key expiration |
| DELETE | `/v1/api-keys/{uuid}` | Revoke a tenant API key (owner/admin; admins cannot revoke owner/admin keys) |
| POST | `/v1/api-keys/{uuid}/rotate` | Replace a key atomically; the old key is revoked and the new secret is shown once |
| GET | `/v1/tenants` | List tenants (product owner sees all; tenant owner sees its own) |
| POST | `/v1/tenants` | Create tenant and issue its initial API key (platform key only) |
| POST | `/v1/tenants/{uuid}/rotate-key` | Revoke old tenant keys and issue a replacement (platform key only) |
| GET | `/v1/tenants/{uuid}/api-keys` | List that tenant's API key metadata (product owner only) |
| PUT | `/v1/tenants/{uuid}/api-keys/{uuid}` | Change or clear one tenant key's expiration (product owner only) |
| DELETE | `/v1/tenants/{uuid}/api-keys/{uuid}` | Revoke one tenant key (product owner only) |
| POST | `/v1/tenants/{uuid}/api-keys/{uuid}/rotate` | Replace one tenant key while preserving its role and expiration (product owner only) |

## Deployment strategy

### Pilot

Deploy the Compose stack on a small private VM with a TLS reverse proxy (Caddy, Traefik, or a managed load balancer). Keep PostgreSQL on a persistent encrypted disk, restrict port 5432 to the API host, and terminate TLS at the proxy. Put `API_KEY` and database credentials in the host's secret manager, not in source control. Back up PostgreSQL daily and test a restore before onboarding responders. Start with one API replica; this service is stateless apart from PostgreSQL.

### Production on Kubernetes

Build the Rust API and Next.js frontend images in CI, scan them, and publish immutable commit-tagged images. Deploy PostgreSQL through a managed service (recommended) with automated backups, point-in-time recovery, encryption, and private networking. Run two or more Next.js frontend replicas and two or more Rust API replicas behind an ingress with TLS; each API replica runs a queue worker, and PostgreSQL row leases coordinate delivery. Configure readiness/liveness probes on `/healthz`, resource requests/limits, a rolling update, and a PodDisruptionBudget. Inject `DATABASE_URL`, `API_KEY`, `SMTP_URL`, `SMTP_FROM`, and `WEBHOOK_SIGNING_SECRET` from the cloud secret manager. Configure the frontend rewrite target as the internal Rust API service URL. Run migrations as a one-shot release job before rolling out the API. Add metrics and alerting for request rate, error rate, database pool saturation, notification dead letters, and time-to-acknowledge.

Example Kubernetes workload outline (supply image and secret values through your platform):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: relayops
spec:
  replicas: 2
  selector:
    matchLabels: { app: relayops }
  template:
    metadata:
      labels: { app: relayops }
    spec:
      containers:
        - name: api
          image: registry.example.com/relayops:COMMIT_SHA
          ports: [{ name: http, containerPort: 8080 }]
          env:
            - name: BIND_ADDR
              value: 0.0.0.0:8080
            - name: DATABASE_URL
              valueFrom: { secretKeyRef: { name: relayops, key: database-url } }
            - name: API_KEY
              valueFrom: { secretKeyRef: { name: relayops, key: api-key } }
            - name: SESSION_COOKIE_SECURE
              value: "true"
            - name: SMTP_URL
              valueFrom: { secretKeyRef: { name: relayops, key: smtp-url, optional: true } }
            - name: SMTP_FROM
              valueFrom: { secretKeyRef: { name: relayops, key: smtp-from, optional: true } }
            - name: WEBHOOK_SIGNING_SECRET
              valueFrom: { secretKeyRef: { name: relayops, key: webhook-signing-secret, optional: true } }
          readinessProbe:
            httpGet: { path: /healthz, port: http }
            initialDelaySeconds: 3
          livenessProbe:
            httpGet: { path: /healthz, port: http }
            initialDelaySeconds: 10
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits: { cpu: "1", memory: 512Mi }
---
apiVersion: v1
kind: Service
metadata:
  name: relayops
spec:
  selector: { app: relayops }
  ports: [{ name: http, port: 80, targetPort: http }]
```

## Roadmap

This code is a starting point, not feature parity. The configuration center's broad connector catalog is not a set of provider adapters. The active delivery adapters are SMTP email and signed HTTPS webhooks. Before broad production use, add SSO/OIDC and user-account membership, per-integration key scoping (tenant roles are available, but keys are not yet bound to individual connectors), tenant-level quotas and audit administration, time-zone-aware on-call rotations, SMS/push/voice and chat/ticketing provider adapters, maintenance windows, suppression rules, alert grouping controls, rate limits, pagination/filtering, SLA analytics, audit export, server-side encrypted connector credential storage, retention controls, secret rotation, and load/security testing. PostgreSQL outbox is suitable for initial deployments; move to Kafka/SQS if sustained throughput requires it.

## Configuration

Required: `DATABASE_URL`, `API_KEY` (platform bootstrap key, at least 24 characters). Optional: `PRODUCT_OWNER_EMAIL` and `PRODUCT_OWNER_PASSWORD` (seeded only if that account does not exist; defaults are for local setup), `SMTP_URL`, `SMTP_FROM`, `WEBHOOK_SIGNING_SECRET` (minimum 32 characters for webhook delivery), `SESSION_COOKIE_SECURE` (set `true` behind HTTPS), `BIND_ADDR` (defaults to `0.0.0.0:8080`), and `RUST_LOG` (defaults to `relayops=info,tower_http=info`).

