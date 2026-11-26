//! Relay workflow: assignment rules, assignment requests, spikes to team leads, team leads,
//! and the demo relay.
//!
//! Identity: the API only knows the logged-in account. A login is matched to a responder handle by
//! e-mail address (an e-mail channel with the same address) or, failing that, by a handle equal to the
//! account's display name. API keys have no personal identity and are never team leads.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{authorized, current_role, require_role, ApiError, AppState};

struct Acting {
    /// Responder handle this login maps to, if any.
    handle: Option<String>,
    /// Name written to the relay timeline.
    label: String,
}

async fn acting(db: &PgPool, headers: &HeaderMap, tenant_id: Uuid) -> Result<Acting, ApiError> {
    let user_id = headers
        .get("x-relayops-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Uuid>().ok());
    let Some(user_id) = user_id else {
        return Ok(Acting { handle: None, label: "api-key".into() });
    };
    let account = sqlx::query_as::<_, (String, String)>("SELECT email,display_name FROM tenant_users WHERE id=$1 AND tenant_id=$2")
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(db)
        .await?;
    let Some((email, display_name)) = account else {
        return Ok(Acting { handle: None, label: "unknown".into() });
    };
    let by_email = sqlx::query_scalar::<_, String>(
        "SELECT handle FROM notification_recipients WHERE tenant_id=$1 AND channel='email' AND lower(destination)=lower($2) ORDER BY handle LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_optional(db)
    .await?;
    let handle = match by_email {
        Some(handle) => Some(handle),
        None => {
            sqlx::query_scalar::<_, String>("SELECT handle FROM notification_recipients WHERE tenant_id=$1 AND lower(handle)=lower($2) ORDER BY handle LIMIT 1")
                .bind(tenant_id)
                .bind(&display_name)
                .fetch_optional(db)
                .await?
        }
    };
    let label = handle.clone().unwrap_or(display_name);
    Ok(Acting { handle, label })
}

async fn is_active_responder(db: &PgPool, tenant_id: Uuid, handle: &str) -> Result<bool, ApiError> {
    let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM notification_recipients WHERE tenant_id=$1 AND handle=$2 AND active)")
        .bind(tenant_id)
        .bind(handle)
        .fetch_one(db)
        .await?;
    Ok(found)
}

/// True when `lead` is the team lead of at least one team or group that `member` belongs to.
async fn is_lead_of(db: &PgPool, tenant_id: Uuid, lead: &str, member: &str) -> Result<bool, ApiError> {
    let found: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
            SELECT 1 FROM notification_team_leads l
            WHERE l.tenant_id=$1 AND l.handle=$2 AND l.team IN (
                SELECT x.t FROM notification_recipients r
                CROSS JOIN LATERAL unnest(r.groups || ARRAY[r.team]) AS x(t)
                WHERE r.tenant_id=$1 AND r.handle=$3 AND btrim(x.t)<>''))"#,
    )
    .bind(tenant_id)
    .bind(lead)
    .bind(member)
    .fetch_one(db)
    .await?;
    Ok(found)
}

/// The team lead a responder should raise a spike to (never the responder themselves).
async fn lead_for(db: &PgPool, tenant_id: Uuid, member: &str) -> Result<Option<String>, ApiError> {
    let lead = sqlx::query_scalar::<_, String>(
        r#"SELECT l.handle FROM notification_team_leads l
           WHERE l.tenant_id=$1 AND l.handle<>$2 AND l.team IN (
               SELECT x.t FROM notification_recipients r
               CROSS JOIN LATERAL unnest(r.groups || ARRAY[r.team]) AS x(t)
               WHERE r.tenant_id=$1 AND r.handle=$2 AND btrim(x.t)<>'')
           ORDER BY l.team LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(member)
    .fetch_optional(db)
    .await?;
    Ok(lead)
}

async fn log_event(conn: &mut sqlx::PgConnection, incident_id: Uuid, kind: &str, actor: &str, note: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO incident_events (incident_id,kind,actor,note) VALUES ($1,$2,$3,$4)")
        .bind(incident_id)
        .bind(kind)
        .bind(actor)
        .bind(note)
        .execute(conn)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- who am I / who can I assign to

pub(crate) async fn me_responder(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let me = acting(&state.db, &headers, tenant_id).await?;
    let led: Vec<String> = match &me.handle {
        Some(handle) => {
            sqlx::query_scalar("SELECT team FROM notification_team_leads WHERE tenant_id=$1 AND handle=$2 ORDER BY team")
                .bind(tenant_id)
                .bind(handle)
                .fetch_all(&state.db)
                .await?
        }
        None => Vec::new(),
    };
    Ok(Json(json!({ "handle": me.handle, "label": me.label, "led_teams": led })))
}

#[derive(Serialize, sqlx::FromRow)]
struct ResponderRow {
    handle: String,
    team: String,
    groups: Vec<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct TeamLeadRow {
    team: String,
    handle: String,
}

/// Responders (without contact details) so every role that can act on relays can pick an assignee.
pub(crate) async fn list_responders(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let responders = sqlx::query_as::<_, ResponderRow>(
        r#"SELECT r.handle,max(r.team) AS team,
           ARRAY(SELECT DISTINCT g.group_name FROM notification_recipients r2 CROSS JOIN LATERAL unnest(r2.groups) AS g(group_name) WHERE r2.tenant_id=$1 AND r2.handle=r.handle ORDER BY g.group_name) AS groups
           FROM notification_recipients r WHERE r.tenant_id=$1 GROUP BY r.handle HAVING bool_or(r.active) ORDER BY r.handle"#,
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await?;
    let leads = sqlx::query_as::<_, TeamLeadRow>("SELECT team,handle FROM notification_team_leads WHERE tenant_id=$1 ORDER BY team")
        .bind(tenant_id)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(json!({ "responders": responders, "leads": leads })))
}

// ---------------------------------------------------------------- team leads

pub(crate) async fn list_team_leads(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let leads = sqlx::query_as::<_, TeamLeadRow>("SELECT team,handle FROM notification_team_leads WHERE tenant_id=$1 ORDER BY team")
        .bind(tenant_id)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(json!({ "leads": leads })))
}

#[derive(Deserialize)]
pub(crate) struct TeamLeadInput {
    handle: String,
}

pub(crate) async fn set_team_lead(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(team): Path<String>,
    Json(input): Json<TeamLeadInput>,
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let team = team.trim().to_string();
    let handle = input.handle.trim().to_string();
    if team.is_empty() || team.len() > 120 || handle.is_empty() || handle.len() > 120 {
        return Err(ApiError::BadRequest("team and handle are required and must be at most 120 characters".into()));
    }
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM notification_recipients r WHERE r.tenant_id=$1 AND r.handle=$2 AND r.active AND (r.team=$3 OR $3=ANY(r.groups)))",
    )
    .bind(tenant_id)
    .bind(&handle)
    .bind(&team)
    .fetch_one(&state.db)
    .await?;
    if !member {
        return Err(ApiError::BadRequest(format!("{handle} must be an active member of {team} to lead it")));
    }
    sqlx::query(
        "INSERT INTO notification_team_leads(tenant_id,team,handle) VALUES($1,$2,$3) ON CONFLICT(tenant_id,team) DO UPDATE SET handle=EXCLUDED.handle,updated_at=now()",
    )
    .bind(tenant_id)
    .bind(&team)
    .bind(&handle)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "lead": { "team": team, "handle": handle } })))
}

pub(crate) async fn clear_team_lead(State(state): State<AppState>, headers: HeaderMap, Path(team): Path<String>) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let result = sqlx::query("DELETE FROM notification_team_leads WHERE tenant_id=$1 AND team=$2")
        .bind(tenant_id)
        .bind(team.trim())
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- assignment

#[derive(Deserialize)]
pub(crate) struct AssignInput {
    assignee: String,
    #[serde(default)]
    note: String,
}

/// Self-assignment and assignment by the assignee's team lead take effect immediately.
/// Anyone else creates a request that the assignee must accept.
pub(crate) async fn assign_incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<AssignInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let assignee = input.assignee.trim().to_string();
    let note = input.note.trim().to_string();
    if assignee.is_empty() || assignee.len() > 120 || note.chars().count() > 500 {
        return Err(ApiError::BadRequest("choose an assignee; the note may be at most 500 characters".into()));
    }
    if !is_active_responder(&state.db, tenant_id, &assignee).await? {
        return Err(ApiError::BadRequest("the assignee must be an active registered responder".into()));
    }
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM incidents WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await?;
    match status.as_deref() {
        None => return Err(ApiError::NotFound),
        Some("resolved") => return Err(ApiError::BadRequest("resolved relays cannot be assigned".into())),
        Some(_) => {}
    }
    let me = acting(&state.db, &headers, tenant_id).await?;
    let direct = match me.handle.as_deref() {
        Some(handle) if handle == assignee => true,
        Some(handle) => is_lead_of(&state.db, tenant_id, handle, &assignee).await?,
        None => false,
    };
    let suffix = if note.is_empty() { String::new() } else { format!(": {note}") };
    let mut tx = state.db.begin().await?;
    if direct {
        sqlx::query("UPDATE incidents SET assignee=$3,updated_at=now() WHERE id=$1 AND tenant_id=$2")
            .bind(id)
            .bind(tenant_id)
            .bind(&assignee)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE incident_assignment_requests SET status='declined',decided_at=now() WHERE incident_id=$1 AND status='pending'")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        log_event(&mut *tx, id, "assigned", &me.label, &format!("Assigned to {assignee}{suffix}")).await?;
        tx.commit().await?;
        return Ok((StatusCode::OK, Json(json!({ "mode": "assigned", "assignee": assignee }))));
    }
    let inserted = sqlx::query(
        "INSERT INTO incident_assignment_requests(tenant_id,incident_id,requested_by,assignee,note) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(&me.label)
    .bind(&assignee)
    .bind(&note)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict(format!("{assignee} has already been asked to take this relay and has not answered yet")));
    }
    log_event(&mut *tx, id, "assignment_requested", &me.label, &format!("Asked {assignee} to take this relay{suffix}")).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "mode": "requested", "assignee": assignee }))))
}

#[derive(Serialize, sqlx::FromRow)]
struct AssignmentRequestRow {
    id: Uuid,
    incident_id: Uuid,
    incident_number: String,
    title: String,
    requested_by: String,
    assignee: String,
    note: String,
    created_at: DateTime<Utc>,
}

pub(crate) async fn list_assignment_requests(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let role = current_role(&headers)?.to_string();
    let me = acting(&state.db, &headers, tenant_id).await?;
    if me.handle.is_none() && role != "owner" && role != "admin" {
        return Ok(Json(json!({ "requests": [] })));
    }
    let rows = sqlx::query_as::<_, AssignmentRequestRow>(
        r#"SELECT q.id,q.incident_id,('RLY-'||lpad(i.incident_number::text,8,'0')) AS incident_number,i.title,q.requested_by,q.assignee,q.note,q.created_at
           FROM incident_assignment_requests q JOIN incidents i ON i.id=q.incident_id
           WHERE q.tenant_id=$1 AND q.status='pending' AND ($2::text IS NULL OR q.assignee=$2 OR q.requested_by=$2)
           ORDER BY q.created_at DESC LIMIT 100"#,
    )
    .bind(tenant_id)
    .bind(me.handle.as_deref())
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "requests": rows })))
}

async fn decide_assignment(state: &AppState, headers: &HeaderMap, id: Uuid, accept: bool) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(headers, &state.api_key)?;
    require_role(headers, &["owner", "admin", "responder"])?;
    let me = acting(&state.db, headers, tenant_id).await?;
    let mut tx = state.db.begin().await?;
    let request = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT incident_id,assignee,requested_by FROM incident_assignment_requests WHERE id=$1 AND tenant_id=$2 AND status='pending' FOR UPDATE",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let (incident_id, assignee, requested_by) = request;
    if me.handle.as_deref() != Some(assignee.as_str()) {
        return Err(ApiError::Denied(format!("only {assignee} can answer this request")));
    }
    if accept {
        let status: String = sqlx::query_scalar("SELECT status FROM incidents WHERE id=$1 AND tenant_id=$2")
            .bind(incident_id)
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;
        if status == "resolved" {
            return Err(ApiError::BadRequest("this relay is already resolved".into()));
        }
        sqlx::query("UPDATE incidents SET assignee=$3,updated_at=now() WHERE id=$1 AND tenant_id=$2")
            .bind(incident_id)
            .bind(tenant_id)
            .bind(&assignee)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE incident_assignment_requests SET status=$2,decided_at=now() WHERE id=$1")
        .bind(id)
        .bind(if accept { "accepted" } else { "declined" })
        .execute(&mut *tx)
        .await?;
    let (kind, note) = if accept {
        ("assignment_accepted", format!("{assignee} accepted the relay requested by {requested_by}"))
    } else {
        ("assignment_declined", format!("{assignee} declined the relay requested by {requested_by}"))
    };
    log_event(&mut *tx, incident_id, kind, &me.label, &note).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn accept_assignment(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    decide_assignment(&state, &headers, id, true).await
}

pub(crate) async fn decline_assignment(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    decide_assignment(&state, &headers, id, false).await
}

// ---------------------------------------------------------------- spikes

#[derive(Deserialize)]
pub(crate) struct SpikeInput {
    reason: String,
}

/// The current assignee flags a mistaken assignment to their team lead.
pub(crate) async fn raise_spike(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SpikeInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let reason = input.reason.trim().to_string();
    if reason.chars().count() < 3 || reason.chars().count() > 1000 {
        return Err(ApiError::BadRequest("explain why this relay was assigned by mistake (3–1000 characters)".into()));
    }
    let row = sqlx::query_as::<_, (String, Option<String>)>("SELECT status,assignee FROM incidents WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.0 == "resolved" {
        return Err(ApiError::BadRequest("resolved relays cannot be spiked".into()));
    }
    let me = acting(&state.db, &headers, tenant_id).await?;
    let Some(handle) = me.handle.clone() else {
        return Err(ApiError::Denied("your login is not linked to a responder; add your login e-mail as an e-mail channel under Users & channels".into()));
    };
    if row.1.as_deref() != Some(handle.as_str()) {
        return Err(ApiError::Denied("only the current assignee can raise a spike on this relay".into()));
    }
    let Some(lead) = lead_for(&state.db, tenant_id, &handle).await? else {
        return Err(ApiError::Conflict("no team lead is set for your team; ask an admin to choose one under Users & channels".into()));
    };
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query("INSERT INTO incident_spikes(tenant_id,incident_id,raised_by,team_lead,reason) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(tenant_id)
        .bind(id)
        .bind(&handle)
        .bind(&lead)
        .bind(&reason)
        .execute(&mut *tx)
        .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict("a spike is already open for this relay".into()));
    }
    log_event(&mut *tx, id, "spike_raised", &handle, &format!("Raised to team lead {lead}: {reason}")).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "team_lead": lead }))))
}

#[derive(Serialize, sqlx::FromRow)]
struct SpikeRow {
    id: Uuid,
    incident_id: Uuid,
    incident_number: String,
    title: String,
    raised_by: String,
    team_lead: String,
    reason: String,
    created_at: DateTime<Utc>,
}

pub(crate) async fn list_spikes(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let role = current_role(&headers)?.to_string();
    let me = acting(&state.db, &headers, tenant_id).await?;
    if me.handle.is_none() && role != "owner" && role != "admin" {
        return Ok(Json(json!({ "spikes": [] })));
    }
    let rows = sqlx::query_as::<_, SpikeRow>(
        r#"SELECT s.id,s.incident_id,('RLY-'||lpad(i.incident_number::text,8,'0')) AS incident_number,i.title,s.raised_by,s.team_lead,s.reason,s.created_at
           FROM incident_spikes s JOIN incidents i ON i.id=s.incident_id
           WHERE s.tenant_id=$1 AND s.status='open' AND ($2::text IS NULL OR s.team_lead=$2 OR s.raised_by=$2)
           ORDER BY s.created_at DESC LIMIT 100"#,
    )
    .bind(tenant_id)
    .bind(me.handle.as_deref())
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "spikes": rows })))
}

#[derive(Deserialize)]
pub(crate) struct SpikeResolveInput {
    /// "reassign" or "dismiss"
    action: String,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    note: String,
}

/// The addressed team lead (or the tenant owner, so a spike can never be stranded) answers a spike.
pub(crate) async fn resolve_spike(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SpikeResolveInput>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let role = current_role(&headers)?.to_string();
    let note = input.note.trim().to_string();
    if note.chars().count() > 1000 {
        return Err(ApiError::BadRequest("the note may be at most 1000 characters".into()));
    }
    if input.action != "reassign" && input.action != "dismiss" {
        return Err(ApiError::BadRequest("action must be reassign or dismiss".into()));
    }
    let me = acting(&state.db, &headers, tenant_id).await?;
    let mut tx = state.db.begin().await?;
    let (incident_id, team_lead, raised_by) = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT incident_id,team_lead,raised_by FROM incident_spikes WHERE id=$1 AND tenant_id=$2 AND status='open' FOR UPDATE",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if me.handle.as_deref() != Some(team_lead.as_str()) && role != "owner" {
        return Err(ApiError::Denied(format!("only team lead {team_lead} can answer this spike")));
    }
    let suffix = if note.is_empty() { String::new() } else { format!(": {note}") };
    if input.action == "reassign" {
        let assignee = input.assignee.as_deref().map(str::trim).unwrap_or_default().to_string();
        if assignee.is_empty() {
            return Err(ApiError::BadRequest("choose who should take the relay".into()));
        }
        if !is_active_responder(&state.db, tenant_id, &assignee).await? {
            return Err(ApiError::BadRequest("the assignee must be an active registered responder".into()));
        }
        sqlx::query("UPDATE incidents SET assignee=$3,updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status<>'resolved'")
            .bind(incident_id)
            .bind(tenant_id)
            .bind(&assignee)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE incident_spikes SET status='reassigned',resolution_note=$2,resolved_at=now() WHERE id=$1")
            .bind(id)
            .bind(&note)
            .execute(&mut *tx)
            .await?;
        log_event(&mut *tx, incident_id, "assigned", &me.label, &format!("Reassigned from {raised_by} to {assignee} after a spike{suffix}")).await?;
    } else {
        sqlx::query("UPDATE incident_spikes SET status='dismissed',resolution_note=$2,resolved_at=now() WHERE id=$1")
            .bind(id)
            .bind(&note)
            .execute(&mut *tx)
            .await?;
        log_event(&mut *tx, incident_id, "spike_dismissed", &me.label, &format!("Spike from {raised_by} dismissed; the relay stays with them{suffix}")).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- demo

#[derive(Deserialize, Default)]
pub(crate) struct DemoInput {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    escalation_policy_id: Option<Uuid>,
}

/// Creates a rehearsal relay. It has no relay route, so nothing is escalated, queued, or sent; the
/// timeline only describes what the chosen route *would* have done.
pub(crate) async fn create_demo_relay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DemoInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let severity = input.severity.unwrap_or_else(|| "warning".into()).to_lowercase();
    if !["critical", "error", "warning", "info"].contains(&severity.as_str()) {
        return Err(ApiError::BadRequest("severity must be critical, error, warning, or info".into()));
    }
    let mut steps: Vec<Value> = Vec::new();
    let mut route_name = String::new();
    if let Some(policy_id) = input.escalation_policy_id {
        let policy = sqlx::query_as::<_, (String, Value)>("SELECT name,steps FROM escalation_policies WHERE id=$1 AND tenant_id=$2")
            .bind(policy_id)
            .bind(tenant_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError::NotFound)?;
        route_name = policy.0;
        steps = policy.1.as_array().cloned().unwrap_or_default();
    }
    let me = acting(&state.db, &headers, tenant_id).await?;
    let dedup_key = format!("demo-{}", Uuid::new_v4());
    let mut tx = state.db.begin().await?;
    let (id, number) = sqlx::query_as::<_, (Uuid, String)>(
        r#"INSERT INTO incidents (tenant_id,dedup_key,title,description,severity,status,source,service,labels,metadata)
           VALUES ($1,$2,'[DEMO] Simulated relay','Rehearsal relay created from the demo flow. Nothing real was sent.',$3,'triggered','demo','demo-service','{"demo":"true"}'::jsonb,'{}'::jsonb)
           RETURNING id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number"#,
    )
    .bind(tenant_id)
    .bind(&dedup_key)
    .bind(&severity)
    .fetch_one(&mut *tx)
    .await?;
    log_event(&mut *tx, id, "demo_started", &me.label, "Demo relay created. No notification will be sent; acknowledge, assign, spike, and resolve it to rehearse the flow.").await?;
    if steps.is_empty() {
        log_event(&mut *tx, id, "demo_notification_simulated", "demo", "No relay route selected, so no one would be notified.").await?;
    }
    for (index, step) in steps.iter().enumerate() {
        let delay = step.get("delay_minutes").and_then(Value::as_i64).unwrap_or(0);
        let target_type = step.get("target_type").and_then(Value::as_str).unwrap_or("target");
        let target = step.get("target").and_then(Value::as_str).unwrap_or("?");
        let when = if delay > 0 { format!("after {delay} min") } else { "immediately".to_string() };
        let note = format!("Route \"{route_name}\" step {}: would notify {target_type} {target} {when}. Nothing was sent.", index + 1);
        log_event(&mut *tx, id, "demo_notification_simulated", "demo", &note).await?;
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "incident_id": id, "incident_number": number, "simulated_steps": steps.len() }))))
}
