use axum::{
    extract::{ Path, Query, Request, State },
    http::{ header, HeaderMap, HeaderValue, Method, StatusCode },
    middleware::Next,
    response::{ IntoResponse, Response },
    Json,
};
use argon2::{
    password_hash::{ PasswordHash, PasswordHasher, PasswordVerifier, SaltString },
    Argon2,
};
use chrono::{ DateTime, Utc };
use serde::{ Deserialize, Serialize };
use serde_json::{ json, Value };
use sha2::{ Digest, Sha256 };
use sqlx::{ postgres::PgPoolOptions, PgPool };
use std::{ env, net::SocketAddr, sync::Arc };
use thiserror::Error;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
mod connectors;
mod notifications;
mod relay_workflow;
mod routes;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    api_key: Arc<String>,
    default_tenant_id: Uuid,
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("invalid request: {0}")] BadRequest(String),
    #[error("conflict: {0}")] Conflict(String),
    #[error("denied: {0}")] Denied(String),
    #[error("database error")] Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized =>
                (
                    StatusCode::UNAUTHORIZED,
                    "authentication required or credentials are invalid".to_string(),
                ),
            ApiError::Forbidden =>
                (StatusCode::FORBIDDEN, "your account role cannot perform this action".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "resource not found".to_string()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::Denied(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::Database(err) => {
                tracing::error!(error = %err, "database operation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
        };
        (status, Json(json!({"error": message}))).into_response()
    }
}

#[derive(Deserialize)]
struct AlertInput {
    /// Stable key from the monitoring system; repeated firing alerts update one incident.
    dedup_key: String,
    title: String,
    #[serde(default)] description: String,
    #[serde(default = "default_severity")] severity: String,
    #[serde(default)] source: String,
    #[serde(default)] service: String,
    #[serde(default)] labels: Value,
    #[serde(default)] metadata: Value,
    #[serde(default)] escalation_policy_id: Option<Uuid>,
}
fn default_severity() -> String {
    "warning".into()
}

#[derive(Serialize, sqlx::FromRow)]
struct Incident {
    id: Uuid,
    incident_number: String,
    dedup_key: String,
    title: String,
    description: String,
    severity: String,
    status: String,
    source: String,
    service: String,
    labels: Value,
    metadata: Value,
    assignee: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    acknowledged_at: Option<DateTime<Utc>>,
    resolved_at: Option<DateTime<Utc>>,
    escalation_policy_id: Option<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
struct IncidentEvent {
    id: i64,
    kind: String,
    actor: String,
    note: String,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct ActionInput {
    #[serde(default)] actor: String,
    #[serde(default)] note: String,
}

async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next
) -> Result<Response, ApiError> {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let (tenant_id, role, key_id, user_id, session_id, is_product_owner) = if
        let Some(token) = bearer
    {
        if token == state.api_key.as_str() {
            (
                state.default_tenant_id,
                "owner".to_string(),
                "platform".to_string(),
                String::new(),
                String::new(),
                true,
            )
        } else {
            let digest = hex::encode(Sha256::digest(token.as_bytes()));
            let row = sqlx
                ::query_as::<_, (Uuid, String, Uuid)>(
                    "UPDATE tenant_api_keys SET last_used_at=now() WHERE key_hash=$1 AND active AND (expires_at IS NULL OR expires_at>now()) RETURNING tenant_id,role,id"
                )
                .bind(digest)
                .fetch_optional(&state.db).await?
                .ok_or(ApiError::Unauthorized)?;
            (row.0, row.1, row.2.to_string(), String::new(), String::new(), false)
        }
    } else {
        let token = request
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|cookie|
                cookie.split(';').find_map(|part| {
                    let (name, value) = part.trim().split_once('=')?;
                    (name == "relayops_session").then_some(value)
                })
            )
            .ok_or(ApiError::Unauthorized)?;
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        sqlx
            ::query_as::<_, (Uuid, String, Uuid, Uuid, bool)>(
                r#"UPDATE user_sessions s SET last_seen_at=now() FROM tenant_users u
            WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.id=s.user_id AND u.active
            RETURNING s.tenant_id,u.role,s.user_id,s.id,u.is_product_owner"#
            )
            .bind(digest)
            .fetch_optional(&state.db).await?
            .map(|(tenant, role, user, session, is_product_owner)| (
                tenant,
                role,
                session.to_string(),
                user.to_string(),
                session.to_string(),
                is_product_owner,
            ))
            .ok_or(ApiError::Unauthorized)?
    };
    request
        .headers_mut()
        .insert(
            "x-relayops-tenant-id",
            HeaderValue::from_bytes(tenant_id.to_string().as_bytes()).map_err(
                |_| ApiError::Unauthorized
            )?
        );
    request
        .headers_mut()
        .insert(
            "x-relayops-role",
            HeaderValue::from_bytes(role.as_bytes()).map_err(|_| ApiError::Unauthorized)?
        );
    request
        .headers_mut()
        .insert(
            "x-relayops-key-id",
            HeaderValue::from_bytes(key_id.as_bytes()).map_err(|_| ApiError::Unauthorized)?
        );
    request
        .headers_mut()
        .insert(
            "x-relayops-user-id",
            HeaderValue::from_bytes(user_id.as_bytes()).map_err(|_| ApiError::Unauthorized)?
        );
    request
        .headers_mut()
        .insert(
            "x-relayops-session-id",
            HeaderValue::from_bytes(session_id.as_bytes()).map_err(|_| ApiError::Unauthorized)?
        );
    request
        .headers_mut()
        .insert(
            "x-relayops-product-owner",
            HeaderValue::from_static(if is_product_owner { "true" } else { "false" })
        );
    Ok(next.run(request).await)
}

fn authorized(headers: &HeaderMap, _key: &str) -> Result<Uuid, ApiError> {
    headers
        .get("x-relayops-tenant-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Uuid>().ok())
        .ok_or(ApiError::Unauthorized)
}

fn require_role(headers: &HeaderMap, allowed: &[&str]) -> Result<(), ApiError> {
    let role = headers
        .get("x-relayops-role")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    if allowed.contains(&role) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
fn current_role(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("x-relayops-role")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)
}

fn require_platform(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let expected = format!("Bearer {}", state.api_key);
    let api_key =
        headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some(expected.as_str());
    let product_owner =
        headers.get("x-relayops-product-owner").and_then(|v| v.to_str().ok()) == Some("true");
    if api_key || product_owner {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}

async fn current_tenant(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let tenant = sqlx
        ::query_as::<_, Tenant>("SELECT id,name,slug,created_at FROM tenants WHERE id=$1")
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    let is_product_owner =
        headers.get("x-relayops-product-owner").and_then(|v| v.to_str().ok()) == Some("true");
    Ok(
        Json(
            json!({"tenant":tenant,"role":current_role(&headers)?,"is_product_owner":is_product_owner})
        )
    )
}

#[derive(Deserialize)]
struct LoginInput {
    tenant_slug: String,
    email: String,
    password: String,
}
#[derive(Deserialize)]
struct RecoverLoginInput {
    email: String,
    password: String,
}
#[derive(Deserialize)]
struct NewLoginAccount {
    email: String,
    display_name: String,
    password: String,
    role: String,
}
#[derive(Serialize, sqlx::FromRow)]
struct LoginAccount {
    id: Uuid,
    email: String,
    display_name: String,
    role: String,
    active: bool,
    is_product_owner: bool,
    created_at: DateTime<Utc>,
}
#[derive(Serialize, sqlx::FromRow)]
struct LoginSession {
    id: Uuid,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    user_agent: String,
    current: bool,
}
#[derive(sqlx::FromRow)]
struct LoginRecord {
    id: Uuid,
    tenant_id: Uuid,
    password_hash: String,
    role: String,
    active: bool,
    is_product_owner: bool,
    failed_login_attempts: i32,
    locked_until: Option<DateTime<Utc>>,
    tenant_name: String,
    tenant_slug: String,
}

fn valid_login_input(email: &str, name: &str, password: &str) -> Result<(), ApiError> {
    if email.trim().is_empty() || email.len() > 320 || email.parse::<lettre::Address>().is_err() {
        return Err(ApiError::BadRequest("enter a valid email address".into()));
    }
    if name.trim().is_empty() || name.len() > 120 {
        return Err(
            ApiError::BadRequest(
                "display name is required and must be at most 120 characters".into()
            )
        );
    }
    if password.len() < 12 || password.len() > 1024 {
        return Err(ApiError::BadRequest("password must be between 12 and 1024 characters".into()));
    }
    Ok(())
}
async fn make_password_hash(password: String) -> Result<String, ApiError> {
    tokio::task
        ::spawn_blocking(move || {
            let salt_bytes = *Uuid::new_v4().as_bytes();
            let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| ApiError::Internal)?;
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|_| ApiError::Internal)
        }).await
        .map_err(|_| ApiError::Internal)?
}
async fn verify_password(password: String, hash: String) -> bool {
    tokio::task
        ::spawn_blocking(move ||
            PasswordHash::new(&hash)
                .ok()
                .is_some_and(|parsed|
                    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
                )
        ).await
        .unwrap_or(false)
}
fn session_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn session_cookie(token: &str, max_age: i64) -> Result<HeaderValue, ApiError> {
    let secure = env::var("SESSION_COOKIE_SECURE").unwrap_or_default().eq_ignore_ascii_case("true");
    let secure_flag = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(
        &format!(
            "relayops_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure_flag}"
        )
    ).map_err(|_| ApiError::Internal)
}
async fn create_login_session(
    db: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    user_agent: &str
) -> Result<(String, Uuid), ApiError> {
    let token = session_token();
    let id = Uuid::new_v4();
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    sqlx
        ::query(
            "INSERT INTO user_sessions(id,tenant_id,user_id,token_hash,expires_at,user_agent) VALUES($1,$2,$3,$4,now()+interval '12 hours',$5)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(digest)
        .bind(user_agent.chars().take(512).collect::<String>())
        .execute(db).await?;
    sqlx
        ::query(
            "UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL AND id IN (SELECT id FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC OFFSET 10)"
        )
        .bind(user_id)
        .execute(db).await?;
    Ok((token, id))
}
async fn insert_login_account(
    db: &PgPool,
    tenant_id: Uuid,
    email: &str,
    name: &str,
    password: &str,
    role: &str
) -> Result<LoginAccount, ApiError> {
    valid_login_input(email, name, password)?;
    if !["owner", "admin", "responder", "viewer"].contains(&role) {
        return Err(ApiError::BadRequest("role must be owner, admin, responder, or viewer".into()));
    }
    let hash = make_password_hash(password.to_string()).await?;
    sqlx::query_as::<_, LoginAccount>(
        "INSERT INTO tenant_users(tenant_id,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING id,email,display_name,role,active,is_product_owner,created_at"
    )
        .bind(tenant_id)
        .bind(email.trim().to_ascii_lowercase())
        .bind(name.trim())
        .bind(hash)
        .bind(role)
        .fetch_one(db).await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.code().as_deref() == Some("23505") {
                    return ApiError::BadRequest(
                        "an account with this email already exists in the tenant".into()
                    );
                }
            }
            ApiError::Database(e)
        })
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>
) -> Result<(HeaderMap, Json<Value>), ApiError> {
    if
        input.tenant_slug.trim().is_empty() ||
        input.tenant_slug.len() > 60 ||
        input.email.trim().is_empty() ||
        input.password.is_empty()
    {
        return Err(ApiError::Unauthorized);
    }
    let account = sqlx
        ::query_as::<_, LoginRecord>(
            r#"SELECT u.id,u.tenant_id,u.password_hash,u.role,u.active,u.is_product_owner,u.failed_login_attempts,u.locked_until,t.name AS tenant_name,t.slug AS tenant_slug
        FROM tenant_users u JOIN tenants t ON t.id=u.tenant_id WHERE t.slug=$1 AND lower(u.email)=lower($2)"#
        )
        .bind(input.tenant_slug.trim())
        .bind(input.email.trim())
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::Unauthorized)?;
    if !account.active || account.locked_until.is_some_and(|until| until > Utc::now()) {
        return Err(ApiError::Unauthorized);
    }
    if !verify_password(input.password.clone(), account.password_hash.clone()).await {
        sqlx
            ::query(
                "UPDATE tenant_users SET failed_login_attempts=failed_login_attempts+1,locked_until=CASE WHEN failed_login_attempts+1>=5 THEN now()+interval '15 minutes' ELSE locked_until END,updated_at=now() WHERE id=$1"
            )
            .bind(account.id)
            .execute(&state.db).await?;
        return Err(ApiError::Unauthorized);
    }
    sqlx
        ::query(
            "UPDATE tenant_users SET failed_login_attempts=0,locked_until=NULL,updated_at=now() WHERE id=$1"
        )
        .bind(account.id)
        .execute(&state.db).await?;
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (token, session_id) = create_login_session(
        &state.db,
        account.tenant_id,
        account.id,
        agent
    ).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::SET_COOKIE, session_cookie(&token, 43200)?);
    Ok((
        response_headers,
        Json(
            json!({"user":{"id":account.id,"email":input.email.trim().to_ascii_lowercase(),"role":account.role,"is_product_owner":account.is_product_owner},"tenant":{"id":account.tenant_id,"name":account.tenant_name,"slug":account.tenant_slug},"session_id":session_id,"expires_in":43200})
        ),
    ))
}

async fn setup_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NewLoginAccount>
) -> Result<(HeaderMap, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let count: i64 = sqlx
        ::query_scalar("SELECT count(*)::bigint FROM tenant_users WHERE tenant_id=$1")
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    if count > 0 {
        return Err(
            ApiError::BadRequest(
                "login setup is already complete. Sign in, or choose Recover access and use a tenant owner API key.".into()
            )
        );
    }
    let user = insert_login_account(
        &state.db,
        tenant_id,
        &input.email,
        &input.display_name,
        &input.password,
        "owner"
    ).await?;
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (token, session_id) = create_login_session(&state.db, tenant_id, user.id, agent).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::SET_COOKIE, session_cookie(&token, 43200)?);
    Ok((response_headers, Json(json!({"user":user,"session_id":session_id,"expires_in":43200}))))
}
async fn recover_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RecoverLoginInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner"])?;
    if
        input.email.trim().is_empty() ||
        input.email.len() > 320 ||
        input.email.parse::<lettre::Address>().is_err()
    {
        return Err(ApiError::BadRequest("enter a valid email address".into()));
    }
    if input.password.len() < 12 || input.password.len() > 1024 {
        return Err(ApiError::BadRequest("password must be between 12 and 1024 characters".into()));
    }
    let hash = make_password_hash(input.password).await?;
    let mut tx = state.db.begin().await?;
    let user_id = sqlx
        ::query_scalar::<_, Uuid>(
            "UPDATE tenant_users SET password_hash=$3,failed_login_attempts=0,locked_until=NULL,updated_at=now() WHERE tenant_id=$1 AND lower(email)=lower($2) AND active RETURNING id"
        )
        .bind(tenant_id)
        .bind(input.email.trim())
        .bind(hash)
        .fetch_optional(&mut *tx).await?;
    if let Some(user_id) = user_id {
        sqlx
            ::query(
                "UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL"
            )
            .bind(user_id)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(
        Json(
            json!({"message":"If the account exists in this tenant, its password was reset and active sessions were revoked."})
        )
    )
}
fn current_user_id(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    headers
        .get("x-relayops-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or(ApiError::Forbidden)
}
fn current_session_id(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    headers
        .get("x-relayops-session-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or(ApiError::Forbidden)
}
async fn auth_me(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let tenant_id = authorized(&headers, &state.api_key)?;
    let user = sqlx
        ::query_as::<_, LoginAccount>(
            "SELECT id,email,display_name,role,active,is_product_owner,created_at FROM tenant_users WHERE id=$1 AND tenant_id=$2 AND active"
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::Unauthorized)?;
    let tenant = sqlx
        ::query_as::<_, Tenant>("SELECT id,name,slug,created_at FROM tenants WHERE id=$1")
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    Ok(Json(json!({"user":user,"tenant":tenant,"session_id":current_session_id(&headers)?})))
}
async fn list_login_sessions(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let current = current_session_id(&headers)?;
    let rows = sqlx
        ::query_as::<_, LoginSession>(
            "SELECT id,created_at,last_seen_at,expires_at,user_agent,(id=$2) AS current FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC"
        )
        .bind(user_id)
        .bind(current)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"sessions":rows})))
}
async fn revoke_login_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let user_id = current_user_id(&headers)?;
    let current = current_session_id(&headers)?;
    let result = sqlx
        ::query(
            "UPDATE user_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL"
        )
        .bind(id)
        .bind(user_id)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let mut response_headers = HeaderMap::new();
    if id == current {
        response_headers.insert(header::SET_COOKIE, session_cookie("", 0)?);
    }
    Ok((response_headers, StatusCode::NO_CONTENT))
}
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let id = current_session_id(&headers)?;
    sqlx
        ::query("UPDATE user_sessions SET revoked_at=now() WHERE id=$1")
        .bind(id)
        .execute(&state.db).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::SET_COOKIE, session_cookie("", 0)?);
    Ok((response_headers, StatusCode::NO_CONTENT))
}
async fn list_login_accounts(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let rows = sqlx
        ::query_as::<_, LoginAccount>(
            "SELECT id,email,display_name,role,active,is_product_owner,created_at FROM tenant_users WHERE tenant_id=$1 ORDER BY display_name,email"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"accounts":rows})))
}
#[derive(Deserialize)]
struct AccountActiveInput {
    active: bool,
}

/// Enables or disables a login account. Disabling also revokes its browser sessions.
async fn set_login_account_active(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<AccountActiveInput>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let actor_role = current_role(&headers)?.to_string();
    if current_user_id(&headers).ok() == Some(id) {
        return Err(ApiError::Denied("you cannot disable or enable your own account".into()));
    }
    let mut tx = state.db.begin().await?;
    let target = sqlx
        ::query_as::<_, (String, bool)>(
            "SELECT role,is_product_owner FROM tenant_users WHERE id=$1 AND tenant_id=$2 FOR UPDATE"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx).await?
        .ok_or(ApiError::NotFound)?;
    let (target_role, is_product_owner) = target;
    if is_product_owner {
        return Err(ApiError::Denied("product owner accounts cannot be changed here".into()));
    }
    if actor_role != "owner" && ["owner", "admin"].contains(&target_role.as_str()) {
        return Err(ApiError::Denied("only an owner can change owner or admin accounts".into()));
    }
    if !input.active && target_role == "owner" {
        let other_owners: i64 = sqlx
            ::query_scalar(
                "SELECT count(*)::bigint FROM tenant_users WHERE tenant_id=$1 AND role='owner' AND active AND id<>$2"
            )
            .bind(tenant_id)
            .bind(id)
            .fetch_one(&mut *tx).await?;
        if other_owners == 0 {
            return Err(
                ApiError::Conflict(
                    "this is the last active owner; create or enable another owner first".into()
                )
            );
        }
    }
    sqlx
        ::query(
            "UPDATE tenant_users SET active=$3,failed_login_attempts=0,locked_until=NULL,updated_at=now() WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.active)
        .execute(&mut *tx).await?;
    if !input.active {
        sqlx
            ::query(
                "UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL"
            )
            .bind(id)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_login_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NewLoginAccount>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let actor = current_role(&headers)?;
    if actor != "owner" && ["owner", "admin"].contains(&input.role.as_str()) {
        return Err(ApiError::Forbidden);
    }
    let user = insert_login_account(
        &state.db,
        tenant_id,
        &input.email,
        &input.display_name,
        &input.password,
        &input.role
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({"account":user}))))
}

async fn create_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AlertInput>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder", "integration"])?;
    if input.dedup_key.trim().is_empty() || input.title.trim().is_empty() {
        return Err(ApiError::BadRequest("dedup_key and title are required".into()));
    }
    let severity = input.severity.to_lowercase();
    if !["critical", "error", "warning", "info"].contains(&severity.as_str()) {
        return Err(
            ApiError::BadRequest("severity must be critical, error, warning, or info".into())
        );
    }
    if let Some(policy_id) = input.escalation_policy_id {
        let exists: bool = sqlx
            ::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM escalation_policies WHERE id=$1 AND tenant_id=$2)"
            )
            .bind(policy_id)
            .bind(tenant_id)
            .fetch_one(&state.db).await?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }
    // Only reopen a resolved incident on a fresh firing; otherwise refresh its details.
    let row = sqlx
        ::query_as::<_, Incident>(
            r#"
        INSERT INTO incidents (tenant_id,dedup_key,title,description,severity,status,source,service,labels,metadata,escalation_policy_id)
        VALUES ($1,$2,$3,$4,$5,'triggered',$6,$7,$8,$9,$10)
        ON CONFLICT (tenant_id,dedup_key) DO UPDATE SET
          title=EXCLUDED.title, description=EXCLUDED.description, severity=EXCLUDED.severity,
          source=EXCLUDED.source, service=EXCLUDED.service, labels=EXCLUDED.labels,
          metadata=EXCLUDED.metadata, updated_at=now(),
          escalation_policy_id=CASE WHEN incidents.status='resolved'
            THEN COALESCE(EXCLUDED.escalation_policy_id,incidents.escalation_policy_id)
            ELSE COALESCE(incidents.escalation_policy_id,EXCLUDED.escalation_policy_id) END,
          status=CASE WHEN incidents.status='resolved' THEN 'triggered' ELSE incidents.status END,
          resolved_at=CASE WHEN incidents.status='resolved' THEN NULL ELSE incidents.resolved_at END
        RETURNING id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number,dedup_key,title,description,severity,status,source,service,labels,metadata,
                  assignee,created_at,updated_at,acknowledged_at,resolved_at,escalation_policy_id
    "#
        )
        .bind(tenant_id)
        .bind(input.dedup_key)
        .bind(input.title)
        .bind(input.description)
        .bind(severity)
        .bind(input.source)
        .bind(input.service)
        .bind(input.labels)
        .bind(input.metadata)
        .bind(input.escalation_policy_id)
        .fetch_one(&state.db).await?;
    if row.status == "triggered" {
        if let Some(policy_id) = row.escalation_policy_id {
            sqlx
                ::query(
                    r#"INSERT INTO incident_escalations (tenant_id,incident_id,policy_id,step_index,cycle,next_run_at,status)
                VALUES ($1,$2,$3,0,0,now(),'active')
                ON CONFLICT (incident_id) DO UPDATE SET id=gen_random_uuid(),policy_id=EXCLUDED.policy_id,
                  tenant_id=EXCLUDED.tenant_id,step_index=0,cycle=0,next_run_at=now(),status='active',last_error='',updated_at=now()
                WHERE incident_escalations.status IN ('completed','cancelled')"#
                )
                .bind(tenant_id)
                .bind(row.id)
                .bind(policy_id)
                .execute(&state.db).await?;
        }
    }
    let status = if row.status == "triggered" && row.created_at == row.updated_at {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(json!({"incident": row}))))
}

#[derive(Deserialize, Default)]
struct IncidentListQuery {
    search: Option<String>,
}

async fn list_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IncidentListQuery>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let total_incidents: i64 = sqlx
        ::query_scalar("SELECT count(*)::bigint FROM incidents WHERE tenant_id=$1")
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    let term = query.search.map(|value| value.trim().to_string()).filter(|value| !value.is_empty());
    if term.as_ref().is_some_and(|value| value.len() > 200) {
        return Err(ApiError::BadRequest("incident search is limited to 200 characters".into()));
    }
    let (rows, matching_incidents) = if let Some(term) = term {
        let pattern = format!("%{}%", term);
        let matching: i64 = sqlx
            ::query_scalar(
                "SELECT count(*)::bigint FROM incidents WHERE tenant_id=$1 AND ((('RLY-'||lpad(incident_number::text,8,'0')) ILIKE $2) OR id::text ILIKE $2 OR title ILIKE $2 OR description ILIKE $2 OR severity ILIKE $2 OR status ILIKE $2 OR source ILIKE $2 OR service ILIKE $2 OR dedup_key ILIKE $2 OR COALESCE(assignee,'') ILIKE $2)"
            )
            .bind(tenant_id)
            .bind(&pattern)
            .fetch_one(&state.db).await?;
        let rows = sqlx
            ::query_as::<_, Incident>(
                r#"SELECT id,dedup_key,title,description,severity,status,source,service,labels,metadata,
            assignee,created_at,updated_at,acknowledged_at,resolved_at,escalation_policy_id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number FROM incidents
            WHERE tenant_id=$1 AND ((('RLY-'||lpad(incident_number::text,8,'0')) ILIKE $2) OR id::text ILIKE $2 OR title ILIKE $2 OR description ILIKE $2 OR severity ILIKE $2 OR status ILIKE $2 OR source ILIKE $2 OR service ILIKE $2 OR dedup_key ILIKE $2 OR COALESCE(assignee,'') ILIKE $2)
            ORDER BY created_at DESC LIMIT 500"#
            )
            .bind(tenant_id)
            .bind(pattern)
            .fetch_all(&state.db).await?;
        (rows, matching)
    } else {
        let rows = sqlx
            ::query_as::<_, Incident>(
                r#"SELECT id,dedup_key,title,description,severity,status,source,service,labels,metadata,
        assignee,created_at,updated_at,acknowledged_at,resolved_at,escalation_policy_id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number FROM incidents WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500"#
            )
            .bind(tenant_id)
            .fetch_all(&state.db).await?;
        (rows, total_incidents)
    };
    Ok(
        Json(
            json!({"incidents": rows,"total_incidents":total_incidents,"matching_incidents":matching_incidents})
        )
    )
}

async fn get_incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let row = sqlx
        ::query_as::<_, Incident>(
            r#"SELECT id,dedup_key,title,description,severity,status,source,service,labels,metadata,
        assignee,created_at,updated_at,acknowledged_at,resolved_at,escalation_policy_id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number FROM incidents WHERE id=$1 AND tenant_id=$2"#
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({"incident": row})))
}

async fn acknowledge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(action): Json<ActionInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let mut tx = state.db.begin().await?;
    let row = sqlx
        ::query_as::<_, Incident>(
            r#"UPDATE incidents SET status='acknowledged',
        assignee=NULLIF($2,''), acknowledged_at=now(), updated_at=now()
        WHERE id=$1 AND tenant_id=$3 AND status IN ('triggered','acknowledged')
        RETURNING id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number,dedup_key,title,description,severity,status,source,service,labels,metadata,assignee,created_at,updated_at,acknowledged_at,resolved_at,escalation_policy_id"#
        )
        .bind(id)
        .bind(&action.actor)
        .bind(tenant_id)
        .fetch_optional(&mut *tx).await?
        .ok_or(ApiError::NotFound)?;
    sqlx
        ::query(
            "INSERT INTO incident_events (incident_id,kind,actor,note) VALUES ($1,'acknowledged',$2,$3)"
        )
        .bind(id)
        .bind(if action.actor.is_empty() { "system" } else { &action.actor })
        .bind(action.note)
        .execute(&mut *tx).await?;
    sqlx
        ::query(
            "UPDATE incident_escalations SET status='cancelled',updated_at=now() WHERE incident_id=$1 AND tenant_id=$2 AND status='active'"
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"incident": row})))
}

async fn resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(action): Json<ActionInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder"])?;
    let resolution = action.note.trim().to_string();
    if resolution.chars().count() < 3 {
        return Err(
            ApiError::BadRequest(
                "a resolution note describing how the relay was resolved is required to complete it".into()
            )
        );
    }
    if resolution.chars().count() > 2000 {
        return Err(
            ApiError::BadRequest("the resolution note may be at most 2000 characters".into())
        );
    }
    let mut tx = state.db.begin().await?;
    let row = sqlx
        ::query_as::<_, Incident>(
            r#"UPDATE incidents SET status='resolved',resolved_at=now(),updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND status <> 'resolved'
        RETURNING id,('RLY-'||lpad(incident_number::text,8,'0')) AS incident_number,dedup_key,title,description,severity,status,source,service,labels,metadata,assignee,created_at,updated_at,acknowledged_at,resolved_at,escalation_policy_id"#
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx).await?
        .ok_or(ApiError::NotFound)?;
    sqlx
        ::query(
            "INSERT INTO incident_events (incident_id,kind,actor,note) VALUES ($1,'resolved',$2,$3)"
        )
        .bind(id)
        .bind(if action.actor.is_empty() { "system" } else { &action.actor })
        .bind(resolution)
        .execute(&mut *tx).await?;
    sqlx
        ::query(
            "UPDATE incident_escalations SET status='cancelled',updated_at=now() WHERE incident_id=$1 AND tenant_id=$2 AND status='active'"
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"incident": row})))
}

#[derive(Serialize, sqlx::FromRow)]
struct NotificationRecipient {
    id: Uuid,
    handle: String,
    channel: String,
    destination: String,
    team: String,
    active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct RecipientInput {
    handle: String,
    channel: String,
    destination: String,
    #[serde(default)] team: String,
    #[serde(default = "default_true")] active: bool,
}
fn default_true() -> bool {
    true
}

#[derive(Serialize, sqlx::FromRow)]
struct NotificationUser {
    handle: String,
    team: String,
    groups: Vec<String>,
    channels: Value,
}

#[derive(Deserialize)]
struct NotificationUserInput {
    #[serde(default)] team: String,
    #[serde(default)] groups: Vec<String>,
    #[serde(default)] email: Option<String>,
    #[serde(default)] webhook: Option<String>,
    #[serde(default = "default_true")] active: bool,
    #[serde(default)] email_active: Option<bool>,
    #[serde(default)] webhook_active: Option<bool>,
    #[serde(default)] slack: Option<String>,
    #[serde(default)] slack_active: Option<bool>,
    #[serde(default)] discord: Option<String>,
    #[serde(default)] discord_active: Option<bool>,
    #[serde(default)] phone: Option<String>,
    #[serde(default)] phone_active: Option<bool>,
    #[serde(default)] mobile: Option<String>,
    #[serde(default)] mobile_active: Option<bool>,
    #[serde(default)] whatsapp: Option<String>,
    #[serde(default)] whatsapp_active: Option<bool>,
}

impl NotificationUserInput {
    /// Every channel a responder can configure, as (channel, destination, per-channel active flag).
    fn channel_values(&self) -> Vec<(&'static str, Option<String>, Option<bool>)> {
        vec![
            ("email", self.email.clone(), self.email_active),
            ("webhook", self.webhook.clone(), self.webhook_active),
            ("slack", self.slack.clone(), self.slack_active),
            ("discord", self.discord.clone(), self.discord_active),
            ("phone", self.phone.clone(), self.phone_active),
            ("mobile", self.mobile.clone(), self.mobile_active),
            ("whatsapp", self.whatsapp.clone(), self.whatsapp_active)
        ]
    }
}

// Deliverable channels: email, webhook, slack, discord (see notifications::is_deliverable_channel).
// Contact-only channels: phone, mobile, whatsapp are stored on the responder but never queued.

/// Accepts international numbers with common separators and returns `+<digits>`.
fn normalize_phone(raw: &str) -> Option<String> {
    let mut digits = String::new();
    for (i, ch) in raw.trim().chars().enumerate() {
        match ch {
            '+' if i == 0 => digits.push('+'),
            '0'..='9' => digits.push(ch),
            ' ' | '-' | '(' | ')' | '.' => {}
            _ => {
                return None;
            }
        }
    }
    let valid = match digits.strip_prefix('+') {
        Some(body) => (7..=15).contains(&body.len()) && !body.starts_with('0'),
        None => false,
    };
    if valid {
        Some(digits)
    } else {
        None
    }
}

/// Validates a destination for a channel and returns the form that should be stored.
fn normalize_channel_destination(channel: &str, destination: &str) -> Result<String, ApiError> {
    let destination = destination.trim();
    if destination.is_empty() || destination.len() > 2048 {
        return Err(
            ApiError::BadRequest(
                "destination is required and must be at most 2048 characters".into()
            )
        );
    }
    match channel {
        "email" => {
            if destination.len() > 320 {
                return Err(ApiError::BadRequest("email address is too long".into()));
            }
            destination
                .parse::<lettre::Address>()
                .map_err(|_|
                    ApiError::BadRequest("email destination must be a valid email address".into())
                )?;
            Ok(destination.to_string())
        }
        "webhook" => {
            let url = reqwest::Url
                ::parse(destination)
                .map_err(|_|
                    ApiError::BadRequest("webhook destination must be a valid HTTPS URL".into())
                )?;
            if
                url.scheme() != "https" ||
                url.host_str().is_none() ||
                url.host_str().unwrap().eq_ignore_ascii_case("localhost")
            {
                return Err(
                    ApiError::BadRequest(
                        "webhook destinations must use HTTPS and a public host".into()
                    )
                );
            }
            Ok(destination.to_string())
        }
        "slack" | "discord" => {
            notifications
                ::validate_chat_webhook(channel, destination)
                .map_err(ApiError::BadRequest)?;
            Ok(destination.to_string())
        }
        "phone" | "mobile" | "whatsapp" =>
            normalize_phone(destination).ok_or_else(|| {
                ApiError::BadRequest(
                    format!(
                        "{channel} destination must be an international number such as +14155550123"
                    )
                )
            }),
        _ =>
            Err(
                ApiError::BadRequest(
                    "channel must be one of email, webhook, slack, discord, phone, mobile, or whatsapp".into()
                )
            ),
    }
}

fn validate_recipient(input: &RecipientInput) -> Result<String, ApiError> {
    if input.handle.trim().is_empty() || input.handle.len() > 120 {
        return Err(
            ApiError::BadRequest("handle is required and must be within length limits".into())
        );
    }
    normalize_channel_destination(&input.channel, &input.destination)
}

async fn list_recipients(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let rows = sqlx
        ::query_as::<_, NotificationRecipient>(
            "SELECT id,handle,channel,destination,team,active,created_at,updated_at FROM notification_recipients WHERE tenant_id=$1 ORDER BY team,handle,channel"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"recipients": rows})))
}

async fn create_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RecipientInput>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let destination = validate_recipient(&input)?;
    let row = sqlx
        ::query_as::<_, NotificationRecipient>(
            "INSERT INTO notification_recipients (tenant_id,handle,channel,destination,team,active) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,handle,channel,destination,team,active,created_at,updated_at"
        )
        .bind(tenant_id)
        .bind(input.handle.trim())
        .bind(input.channel)
        .bind(destination)
        .bind(input.team.trim())
        .bind(input.active)
        .fetch_one(&state.db).await?;
    Ok((StatusCode::CREATED, Json(json!({"recipient": row}))))
}

async fn update_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RecipientInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let destination = validate_recipient(&input)?;
    let row = sqlx
        ::query_as::<_, NotificationRecipient>(
            "UPDATE notification_recipients SET handle=$3,channel=$4,destination=$5,team=$6,active=$7,updated_at=now() WHERE id=$1 AND tenant_id=$2 RETURNING id,handle,channel,destination,team,active,created_at,updated_at"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.handle.trim())
        .bind(input.channel)
        .bind(destination)
        .bind(input.team.trim())
        .bind(input.active)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({"recipient": row})))
}

async fn delete_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let result = sqlx
        ::query(
            "UPDATE notification_recipients SET active=false,updated_at=now() WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_notification_users(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let users = sqlx
        ::query_as::<_, NotificationUser>(
            r#"SELECT r.handle,max(r.team) AS team,
        ARRAY(SELECT DISTINCT g.group_name FROM notification_recipients r2 CROSS JOIN LATERAL unnest(r2.groups) AS g(group_name) WHERE r2.tenant_id=$1 AND r2.handle=r.handle ORDER BY g.group_name) AS groups,
        jsonb_object_agg(r.channel,jsonb_build_object('destination',r.destination,'active',r.active)) AS channels
        FROM notification_recipients r WHERE r.tenant_id=$1 GROUP BY r.handle ORDER BY r.handle"#
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"users":users})))
}

fn validate_user(handle: &str, input: &NotificationUserInput) -> Result<(), ApiError> {
    if handle.trim().is_empty() || handle.len() > 120 || input.team.len() > 120 {
        return Err(
            ApiError::BadRequest("user handle and team must be within length limits".into())
        );
    }
    if
        input.groups.len() > 20 ||
        input.groups.iter().any(|g| (g.trim().is_empty() || g.len() > 120))
    {
        return Err(
            ApiError::BadRequest(
                "users may belong to at most 20 non-empty groups of at most 120 characters".into()
            )
        );
    }
    let mut configured = false;
    for (channel, destination, _) in input.channel_values() {
        if let Some(destination) = destination.filter(|v| !v.trim().is_empty()) {
            normalize_channel_destination(channel, &destination)?;
            configured = true;
        }
    }
    if !configured {
        return Err(
            ApiError::BadRequest(
                "configure at least one channel: email, webhook, slack, discord, phone, mobile, or whatsapp".into()
            )
        );
    }
    Ok(())
}

async fn persist_user(
    db: &PgPool,
    tenant_id: Uuid,
    handle: &str,
    input: NotificationUserInput
) -> Result<NotificationUser, ApiError> {
    validate_user(handle, &input)?;
    let mut groups = input.groups.clone();
    if groups.is_empty() && !input.team.trim().is_empty() {
        groups.push(input.team.trim().to_string());
    }
    groups = groups
        .into_iter()
        .map(|g| g.trim().to_string())
        .collect();
    groups.sort();
    groups.dedup();
    let mut tx = db.begin().await?;
    for (channel, destination, active_flag) in input.channel_values() {
        if let Some(destination) = destination.filter(|v| !v.trim().is_empty()) {
            let destination = normalize_channel_destination(channel, &destination)?;
            let channel_active = input.active && active_flag.unwrap_or(true);
            sqlx
                ::query(
                    r#"INSERT INTO notification_recipients(tenant_id,handle,channel,destination,team,groups,active)
                VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,handle,channel) DO UPDATE SET
                destination=EXCLUDED.destination,team=EXCLUDED.team,groups=EXCLUDED.groups,active=EXCLUDED.active,updated_at=now()"#
                )
                .bind(tenant_id)
                .bind(handle.trim())
                .bind(channel)
                .bind(destination.trim())
                .bind(input.team.trim())
                .bind(&groups)
                .bind(channel_active)
                .execute(&mut *tx).await?;
        } else {
            sqlx
                ::query(
                    "UPDATE notification_recipients SET active=false,team=$4,groups=$5,updated_at=now() WHERE tenant_id=$1 AND handle=$2 AND channel=$3"
                )
                .bind(tenant_id)
                .bind(handle.trim())
                .bind(channel)
                .bind(input.team.trim())
                .bind(&groups)
                .execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    let user = sqlx
        ::query_as::<_, NotificationUser>(
            r#"SELECT r.handle,max(r.team) AS team,
        ARRAY(SELECT DISTINCT g.group_name FROM notification_recipients r2 CROSS JOIN LATERAL unnest(r2.groups) AS g(group_name) WHERE r2.tenant_id=$1 AND r2.handle=r.handle ORDER BY g.group_name) AS groups,
        jsonb_object_agg(r.channel,jsonb_build_object('destination',r.destination,'active',r.active)) AS channels
        FROM notification_recipients r WHERE r.tenant_id=$1 AND r.handle=$2 GROUP BY r.handle"#
        )
        .bind(tenant_id)
        .bind(handle.trim())
        .fetch_one(db).await?;
    Ok(user)
}

async fn existing_groups(db: &PgPool, tenant_id: Uuid) -> Result<Vec<String>, ApiError> {
    let rows = sqlx
        ::query_scalar::<_, String>(
            "SELECT DISTINCT g.group_name FROM notification_recipients r CROSS JOIN LATERAL unnest(r.groups) AS g(group_name) WHERE r.tenant_id=$1"
        )
        .bind(tenant_id)
        .fetch_all(db).await?;
    Ok(rows)
}

/// Creates a "Default · <name>" relay route for a new responder and for every group that did not exist before.
/// Existing routes with the same name are left untouched, so deleting a default route is never undone by an edit.
async fn ensure_default_routes(
    db: &PgPool,
    tenant_id: Uuid,
    handle: &str,
    groups: &[String],
    known_groups: &[String],
    include_user: bool
) -> Result<(), ApiError> {
    let mut targets: Vec<(String, &str, String)> = Vec::new();
    if include_user {
        targets.push((format!("Default · {handle}"), "user", handle.to_string()));
    }
    for group in groups {
        if !known_groups.contains(group) {
            targets.push((format!("Default · {group}"), "team", group.clone()));
        }
    }
    for (name, target_type, target) in targets {
        sqlx
            ::query(
                r#"INSERT INTO escalation_policies(tenant_id,name,description,timezone,repeat_count,repeat_every_minutes,steps)
            SELECT $1::uuid,$2::text,$3::text,'UTC',0,30,$4::jsonb
            WHERE NOT EXISTS (SELECT 1 FROM escalation_policies WHERE tenant_id=$1::uuid AND name=$2::text)"#
            )
            .bind(tenant_id)
            .bind(&name)
            .bind(format!("Created automatically for {target_type} {target}."))
            .bind(json!([{"delay_minutes":0,"target_type":target_type,"target":target}]))
            .execute(db).await?;
    }
    Ok(())
}

async fn create_notification_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<serde_json::Value>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let handle = input
        .get("handle")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest("handle is required".into()))?
        .to_string();
    let config: NotificationUserInput = serde_json
        ::from_value(input)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let known_groups = existing_groups(&state.db, tenant_id).await?;
    let user = persist_user(&state.db, tenant_id, &handle, config).await?;
    ensure_default_routes(
        &state.db,
        tenant_id,
        &user.handle,
        &user.groups,
        &known_groups,
        true
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({"user":user}))))
}

async fn update_notification_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(input): Json<NotificationUserInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let known_groups = existing_groups(&state.db, tenant_id).await?;
    let user = persist_user(&state.db, tenant_id, &handle, input).await?;
    ensure_default_routes(
        &state.db,
        tenant_id,
        &user.handle,
        &user.groups,
        &known_groups,
        false
    ).await?;
    Ok(Json(json!({"user":user})))
}

#[derive(Deserialize)]
struct RemoveUserQuery {
    #[serde(default)] permanent: bool,
}

/// Permanently deletes a responder after checking that no schedule or relay route still depends on them.
async fn remove_notification_user(
    db: &PgPool,
    tenant_id: Uuid,
    handle: &str
) -> Result<StatusCode, ApiError> {
    let existing: i64 = sqlx
        ::query_scalar(
            "SELECT count(*)::bigint FROM notification_recipients WHERE tenant_id=$1 AND handle=$2"
        )
        .bind(tenant_id)
        .bind(handle)
        .fetch_one(db).await?;
    if existing == 0 {
        return Err(ApiError::NotFound);
    }
    let default_name = format!("Default · {handle}");
    let schedules = sqlx
        ::query_scalar::<_, String>(
            "SELECT s.name FROM on_call_schedules s JOIN on_call_schedule_members m ON m.schedule_id=s.id WHERE s.tenant_id=$1 AND m.handle=$2 ORDER BY s.name"
        )
        .bind(tenant_id)
        .bind(handle)
        .fetch_all(db).await?;
    let routes = sqlx
        ::query_scalar::<_, String>(
            r#"SELECT p.name FROM escalation_policies p WHERE p.tenant_id=$1 AND p.name<>$3
        AND EXISTS (SELECT 1 FROM jsonb_array_elements(p.steps) st WHERE st->>'target_type'='user' AND st->>'target'=$2) ORDER BY p.name"#
        )
        .bind(tenant_id)
        .bind(handle)
        .bind(&default_name)
        .fetch_all(db).await?;
    if !schedules.is_empty() || !routes.is_empty() {
        let mut parts: Vec<String> = Vec::new();
        if !schedules.is_empty() {
            parts.push(format!("on-call schedule(s): {}", schedules.join(", ")));
        }
        if !routes.is_empty() {
            parts.push(format!("relay route(s): {}", routes.join(", ")));
        }
        return Err(
            ApiError::Conflict(
                format!(
                    "{handle} is still used by {}. Remove them from there first, or pause the responder instead.",
                    parts.join("; ")
                )
            )
        );
    }
    let mut tx = db.begin().await?;
    sqlx
        ::query(
            "UPDATE notification_outbox SET status='cancelled',locked_at=NULL,last_error='recipient removed' WHERE tenant_id=$1 AND status IN ('pending','sending') AND recipient_id IN (SELECT id FROM notification_recipients WHERE tenant_id=$1 AND handle=$2)"
        )
        .bind(tenant_id)
        .bind(handle)
        .execute(&mut *tx).await?;
    sqlx
        ::query("DELETE FROM notification_recipients WHERE tenant_id=$1 AND handle=$2")
        .bind(tenant_id)
        .bind(handle)
        .execute(&mut *tx).await?;
    sqlx
        ::query("DELETE FROM notification_team_leads WHERE tenant_id=$1 AND handle=$2")
        .bind(tenant_id)
        .bind(handle)
        .execute(&mut *tx).await?;
    sqlx
        ::query("DELETE FROM escalation_policies WHERE tenant_id=$1 AND name=$2")
        .bind(tenant_id)
        .bind(&default_name)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn deactivate_notification_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Query(query): Query<RemoveUserQuery>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    if query.permanent {
        return remove_notification_user(&state.db, tenant_id, handle.trim()).await;
    }
    let result = sqlx
        ::query(
            "UPDATE notification_recipients SET active=false,updated_at=now() WHERE tenant_id=$1 AND handle=$2"
        )
        .bind(tenant_id)
        .bind(handle)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
struct DeliveryAttempt {
    id: Uuid,
    incident_id: Uuid,
    channel: String,
    destination: String,
    status: String,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
    last_error: String,
    created_at: DateTime<Utc>,
}

async fn list_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let rows = sqlx
        ::query_as::<_, DeliveryAttempt>(
            "SELECT id,incident_id,channel,destination,status,attempts,max_attempts,next_attempt_at,delivered_at,last_error,created_at FROM notification_outbox WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"deliveries": rows})))
}

async fn retry_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let result = sqlx
        ::query(
            "UPDATE notification_outbox SET status='pending',attempts=0,next_attempt_at=now(),locked_at=NULL,last_error='' WHERE id=$1 AND tenant_id=$2 AND status='dead'"
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let rows = sqlx
        ::query_as::<_, IncidentEvent>(
            "SELECT e.id,e.kind,e.actor,e.note,e.created_at FROM incident_events e JOIN incidents i ON i.id=e.incident_id WHERE e.incident_id=$1 AND i.tenant_id=$2 ORDER BY e.created_at"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"events": rows})))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EscalationStep {
    delay_minutes: i32,
    target_type: String,
    target: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct EscalationPolicy {
    id: Uuid,
    name: String,
    description: String,
    timezone: String,
    repeat_count: i32,
    repeat_every_minutes: i32,
    steps: Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct EscalationPolicyInput {
    name: String,
    #[serde(default)] description: String,
    timezone: String,
    #[serde(default)] repeat_count: i32,
    #[serde(default = "default_repeat_minutes")] repeat_every_minutes: i32,
    steps: Vec<EscalationStep>,
}

#[derive(Deserialize)]
struct OnCallScheduleInput {
    name: String,
    timezone: String,
    rotation_interval_minutes: i32,
    rotation_starts_at: DateTime<Utc>,
    members: Vec<String>,
    #[serde(default)] team: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct OnCallSchedule {
    id: Uuid,
    name: String,
    timezone: String,
    rotation_interval_minutes: i32,
    rotation_starts_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn validate_schedule(input: &mut OnCallScheduleInput) -> Result<(), ApiError> {
    use std::str::FromStr;
    input.name = input.name.trim().to_string();
    input.team = input.team.trim().to_string();
    if input.team.len() > 120 {
        return Err(ApiError::BadRequest("schedule team must be at most 120 characters".into()));
    }
    input.members = input.members
        .iter()
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect();
    if input.name.is_empty() || input.name.len() > 120 {
        return Err(
            ApiError::BadRequest(
                "schedule name is required and must be at most 120 characters".into()
            )
        );
    }
    if chrono_tz::Tz::from_str(&input.timezone).is_err() {
        return Err(ApiError::BadRequest("timezone must be a valid IANA time zone".into()));
    }
    if !(15..=43200).contains(&input.rotation_interval_minutes) {
        return Err(
            ApiError::BadRequest("rotation_interval_minutes must be between 15 and 43200".into())
        );
    }
    if input.members.is_empty() || input.members.len() > 50 {
        return Err(ApiError::BadRequest("a schedule requires 1–50 responder handles".into()));
    }
    let mut unique = input.members.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != input.members.len() {
        return Err(ApiError::BadRequest("schedule members must be unique".into()));
    }
    Ok(())
}

async fn schedule_json(db: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<Value, ApiError> {
    let schedule = sqlx
        ::query_as::<_, OnCallSchedule>(
            "SELECT id,name,timezone,rotation_interval_minutes,rotation_starts_at,created_at,updated_at FROM on_call_schedules WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(db).await?;
    let members = sqlx
        ::query_scalar::<_, String>(
            "SELECT handle FROM on_call_schedule_members WHERE schedule_id=$1 ORDER BY position"
        )
        .bind(id)
        .fetch_all(db).await?;
    let team: String = sqlx
        ::query_scalar("SELECT team FROM on_call_schedules WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .fetch_one(db).await?;
    Ok(
        json!({"id":schedule.id,"name":schedule.name,"team":team,"timezone":schedule.timezone,"rotation_interval_minutes":schedule.rotation_interval_minutes,"rotation_starts_at":schedule.rotation_starts_at,"members":members,"created_at":schedule.created_at,"updated_at":schedule.updated_at})
    )
}

async fn validate_schedule_members(
    db: &PgPool,
    tenant_id: Uuid,
    members: &[String],
    team: &str
) -> Result<(), ApiError> {
    let count: i64 = sqlx
        ::query_scalar(
            "SELECT count(DISTINCT handle)::bigint FROM notification_recipients WHERE tenant_id=$1 AND active AND channel IN ('email','webhook','slack','discord') AND handle=ANY($2)"
        )
        .bind(tenant_id)
        .bind(members.to_vec())
        .fetch_one(db).await?;
    if count != (members.len() as i64) {
        return Err(
            ApiError::BadRequest(
                "every schedule member must have at least one active deliverable channel (email, webhook, Slack, or Discord) in this tenant".into()
            )
        );
    }
    if !team.is_empty() {
        let elsewhere: Vec<String> = sqlx
            ::query_scalar(
                "SELECT DISTINCT handle FROM notification_recipients WHERE tenant_id=$1 AND handle=ANY($2) AND (btrim(team)<>'' OR cardinality(groups)>0) AND NOT (team=$3 OR $3=ANY(groups)) ORDER BY handle"
            )
            .bind(tenant_id)
            .bind(members.to_vec())
            .bind(team)
            .fetch_all(db).await?;
        if !elsewhere.is_empty() {
            return Err(
                ApiError::BadRequest(
                    format!(
                        "{} belong to another team and cannot join the {team} rotation",
                        elsewhere.join(", ")
                    )
                )
            );
        }
    }
    Ok(())
}

async fn list_schedules(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let ids = sqlx
        ::query_scalar::<_, Uuid>(
            "SELECT id FROM on_call_schedules WHERE tenant_id=$1 ORDER BY name"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    let mut schedules = Vec::with_capacity(ids.len());
    for id in ids {
        schedules.push(schedule_json(&state.db, tenant_id, id).await?);
    }
    Ok(Json(json!({"schedules":schedules})))
}

async fn create_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<OnCallScheduleInput>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    validate_schedule(&mut input)?;
    validate_schedule_members(&state.db, tenant_id, &input.members, &input.team).await?;
    let mut tx = state.db.begin().await?;
    let schedule = sqlx
        ::query_as::<_, OnCallSchedule>(
            "INSERT INTO on_call_schedules(tenant_id,name,timezone,rotation_interval_minutes,rotation_starts_at,team) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,timezone,rotation_interval_minutes,rotation_starts_at,created_at,updated_at"
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.timezone)
        .bind(input.rotation_interval_minutes)
        .bind(input.rotation_starts_at)
        .bind(&input.team)
        .fetch_one(&mut *tx).await
        .map_err(|e| {
            if let sqlx::Error::Database(d) = &e {
                if d.code().as_deref() == Some("23505") {
                    return ApiError::BadRequest("a schedule with this name already exists".into());
                }
            }
            ApiError::Database(e)
        })?;
    for (position, handle) in input.members.iter().enumerate() {
        sqlx
            ::query(
                "INSERT INTO on_call_schedule_members(schedule_id,position,handle) VALUES($1,$2,$3)"
            )
            .bind(schedule.id)
            .bind(position as i32)
            .bind(handle)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"schedule":schedule_json(&state.db,tenant_id,schedule.id).await?})),
    ))
}

async fn update_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(mut input): Json<OnCallScheduleInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    validate_schedule(&mut input)?;
    validate_schedule_members(&state.db, tenant_id, &input.members, &input.team).await?;
    let mut tx = state.db.begin().await?;
    let exists = sqlx
        ::query(
            "UPDATE on_call_schedules SET name=$3,timezone=$4,rotation_interval_minutes=$5,rotation_starts_at=$6,team=$7,updated_at=now() WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.timezone)
        .bind(input.rotation_interval_minutes)
        .bind(input.rotation_starts_at)
        .bind(&input.team)
        .execute(&mut *tx).await?;
    if exists.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx
        ::query("DELETE FROM on_call_schedule_members WHERE schedule_id=$1")
        .bind(id)
        .execute(&mut *tx).await?;
    for (position, handle) in input.members.iter().enumerate() {
        sqlx
            ::query(
                "INSERT INTO on_call_schedule_members(schedule_id,position,handle) VALUES($1,$2,$3)"
            )
            .bind(id)
            .bind(position as i32)
            .bind(handle)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"schedule":schedule_json(&state.db,tenant_id,id).await?})))
}

async fn delete_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let result = sqlx
        ::query("DELETE FROM on_call_schedules WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
fn default_repeat_minutes() -> i32 {
    30
}

fn validate_policy(input: &EscalationPolicyInput) -> Result<(), ApiError> {
    use std::str::FromStr;
    if input.name.trim().is_empty() || input.name.len() > 120 {
        return Err(ApiError::BadRequest("policy name is required (max 120 characters)".into()));
    }
    if chrono_tz::Tz::from_str(&input.timezone).is_err() {
        return Err(ApiError::BadRequest("timezone must be a valid IANA time zone".into()));
    }
    if
        input.repeat_count < 0 ||
        input.repeat_count > 20 ||
        !(1..=10080).contains(&input.repeat_every_minutes)
    {
        return Err(
            ApiError::BadRequest(
                "repeat_count must be 0–20 and repeat_every_minutes must be 1–10080".into()
            )
        );
    }
    if input.steps.is_empty() || input.steps.len() > 10 {
        return Err(ApiError::BadRequest("a policy must have 1–10 escalation steps".into()));
    }
    for step in &input.steps {
        if !(0..=10080).contains(&step.delay_minutes) {
            return Err(ApiError::BadRequest("step delay must be 0–10080 minutes".into()));
        }
        if !["user", "team", "schedule", "channel"].contains(&step.target_type.as_str()) {
            return Err(
                ApiError::BadRequest("target_type must be user, team, schedule, or channel".into())
            );
        }
        if step.target.trim().is_empty() || step.target.len() > 255 {
            return Err(
                ApiError::BadRequest(
                    "every escalation step needs a target (max 255 characters)".into()
                )
            );
        }
    }
    Ok(())
}

async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let rows = sqlx
        ::query_as::<_, EscalationPolicy>(
            "SELECT id,name,description,timezone,repeat_count,repeat_every_minutes,steps,created_at,updated_at FROM escalation_policies WHERE tenant_id=$1 ORDER BY name"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"policies": rows})))
}

async fn create_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EscalationPolicyInput>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    validate_policy(&input)?;
    let row = sqlx
        ::query_as::<_, EscalationPolicy>(
            "INSERT INTO escalation_policies (tenant_id,name,description,timezone,repeat_count,repeat_every_minutes,steps) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,description,timezone,repeat_count,repeat_every_minutes,steps,created_at,updated_at"
        )
        .bind(tenant_id)
        .bind(input.name.trim())
        .bind(input.description.trim())
        .bind(input.timezone)
        .bind(input.repeat_count)
        .bind(input.repeat_every_minutes)
        .bind(json!(input.steps))
        .fetch_one(&state.db).await?;
    Ok((StatusCode::CREATED, Json(json!({"policy": row}))))
}

async fn update_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<EscalationPolicyInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    validate_policy(&input)?;
    let row = sqlx
        ::query_as::<_, EscalationPolicy>(
            "UPDATE escalation_policies SET name=$3,description=$4,timezone=$5,repeat_count=$6,repeat_every_minutes=$7,steps=$8,updated_at=now() WHERE id=$1 AND tenant_id=$2 RETURNING id,name,description,timezone,repeat_count,repeat_every_minutes,steps,created_at,updated_at"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.name.trim())
        .bind(input.description.trim())
        .bind(input.timezone)
        .bind(input.repeat_count)
        .bind(input.repeat_every_minutes)
        .bind(json!(input.steps))
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({"policy": row})))
}

async fn delete_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let result = sqlx
        ::query("DELETE FROM escalation_policies WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
struct TenantKeyInfo {
    id: Uuid,
    name: String,
    role: String,
    active: bool,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}
#[derive(Deserialize)]
struct NewTenantKey {
    name: String,
    role: String,
    expires_at: Option<DateTime<Utc>>,
}

fn validate_key_expiration(expires_at: Option<DateTime<Utc>>) -> Result<(), ApiError> {
    if expires_at.as_ref().is_some_and(|value| *value <= Utc::now()) {
        return Err(ApiError::BadRequest("API key expiration must be in the future".into()));
    }
    Ok(())
}

async fn list_tenant_keys(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let rows = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "SELECT id,name,role,active AND (expires_at IS NULL OR expires_at>now()) AS active,created_at,last_used_at,expires_at FROM tenant_api_keys WHERE tenant_id=$1 ORDER BY created_at"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"api_keys":rows})))
}

async fn create_tenant_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NewTenantKey>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let actor = current_role(&headers)?;
    if
        input.name.trim().is_empty() ||
        input.name.len() > 120 ||
        !["owner", "admin", "responder", "integration", "viewer"].contains(&input.role.as_str())
    {
        return Err(
            ApiError::BadRequest(
                "key name is required and role must be owner, admin, responder, integration, or viewer".into()
            )
        );
    }
    validate_key_expiration(input.expires_at)?;
    if actor != "owner" && ["owner", "admin"].contains(&input.role.as_str()) {
        return Err(ApiError::Forbidden);
    }
    let key = new_api_key();
    let row = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "INSERT INTO tenant_api_keys(tenant_id,name,key_hash,role,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id,name,role,active,created_at,last_used_at,expires_at"
        )
        .bind(tenant_id)
        .bind(input.name.trim())
        .bind(hash_api_key(&key))
        .bind(input.role)
        .bind(input.expires_at)
        .fetch_one(&state.db).await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"api_key":row,"secret":key,"warning":"Save this secret now; it is shown only once."})
        ),
    ))
}

#[derive(Deserialize)]
struct UpdateTenantKey {
    #[serde(deserialize_with = "deserialize_expiration")] expires_at: Option<DateTime<Utc>>,
}

fn deserialize_expiration<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where D: serde::Deserializer<'de>
{
    Option::<DateTime<Utc>>::deserialize(deserializer)
}

async fn update_tenant_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateTenantKey>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let actor = current_role(&headers)?;
    let current = sqlx
        ::query_scalar::<_, String>("SELECT role FROM tenant_api_keys WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    if actor == "admin" && ["owner", "admin"].contains(&current.as_str()) {
        return Err(ApiError::Forbidden);
    }
    validate_key_expiration(input.expires_at)?;
    let row = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "UPDATE tenant_api_keys SET expires_at=$3 WHERE id=$1 AND tenant_id=$2 RETURNING id,name,role,active AND (expires_at IS NULL OR expires_at>now()) AS active,created_at,last_used_at,expires_at"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.expires_at)
        .fetch_one(&state.db).await?;
    Ok(Json(json!({"api_key":row})))
}

async fn rotate_individual_tenant_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let actor = current_role(&headers)?;
    let existing = sqlx
        ::query_as::<_, (String, String, bool, Option<DateTime<Utc>>)>(
            "SELECT name,role,active,expires_at FROM tenant_api_keys WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    if actor == "admin" && ["owner", "admin"].contains(&existing.1.as_str()) {
        return Err(ApiError::Forbidden);
    }
    if !existing.2 || existing.3.as_ref().is_some_and(|expires| *expires <= Utc::now()) {
        return Err(ApiError::BadRequest("an inactive or expired key cannot be rotated".into()));
    }
    let replacement = new_api_key();
    let mut tx = state.db.begin().await?;
    sqlx
        ::query("UPDATE tenant_api_keys SET active=false WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx).await?;
    let row = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "INSERT INTO tenant_api_keys(tenant_id,name,key_hash,role,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id,name,role,active,created_at,last_used_at,expires_at"
        )
        .bind(tenant_id)
        .bind(existing.0)
        .bind(hash_api_key(&replacement))
        .bind(existing.1)
        .bind(existing.3)
        .fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let id_text = id.to_string();
    let current_key_id = headers.get("x-relayops-key-id").and_then(|value| value.to_str().ok());
    let rotated_current_key = current_key_id == Some(id_text.as_str());
    Ok(
        Json(
            json!({"api_key":row,"secret":replacement,"rotated_current_key":rotated_current_key,"warning":"The previous key is revoked. Save this replacement secret now; it is shown only once."})
        )
    )
}

async fn revoke_tenant_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let key = sqlx
        ::query_as::<_, (String, bool)>(
            "SELECT role,active AND (expires_at IS NULL OR expires_at>now()) FROM tenant_api_keys WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    let actor = current_role(&headers)?;
    if actor == "admin" && ["owner", "admin"].contains(&key.0.as_str()) {
        return Err(ApiError::Forbidden);
    }
    if key.0 == "owner" && key.1 {
        let owners: i64 = sqlx
            ::query_scalar(
                "SELECT count(*) FROM tenant_api_keys WHERE tenant_id=$1 AND active AND role='owner' AND (expires_at IS NULL OR expires_at>now()) AND id<>$2"
            )
            .bind(tenant_id)
            .bind(id)
            .fetch_one(&state.db).await?;
        if owners == 0 {
            return Err(
                ApiError::BadRequest("a tenant must retain at least one active owner key".into())
            );
        }
    }
    let current = headers.get("x-relayops-key-id").and_then(|v| v.to_str().ok());
    let id_text = id.to_string();
    if current == Some(id_text.as_str()) {
        return Err(
            ApiError::BadRequest(
                "this API key cannot revoke itself; use a different owner key".into()
            )
        );
    }
    sqlx
        ::query("UPDATE tenant_api_keys SET active=false WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
struct Tenant {
    id: Uuid,
    name: String,
    slug: String,
    created_at: DateTime<Utc>,
}
#[derive(Deserialize)]
struct NewTenant {
    name: String,
    slug: String,
}
fn new_api_key() -> String {
    format!("rly_{}_{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn hash_api_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

async fn list_tenants(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let rows = if require_platform(&headers, &state).is_ok() {
        sqlx
            ::query_as::<_, Tenant>(
                "SELECT id,name,slug,created_at FROM tenants ORDER BY created_at"
            )
            .fetch_all(&state.db).await?
    } else {
        require_role(&headers, &["owner"])?;
        let tenant_id = authorized(&headers, &state.api_key)?;
        sqlx
            ::query_as::<_, Tenant>("SELECT id,name,slug,created_at FROM tenants WHERE id=$1")
            .bind(tenant_id)
            .fetch_all(&state.db).await?
    };
    Ok(Json(json!({"tenants":rows})))
}

async fn create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NewTenant>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_platform(&headers, &state)?;
    let slug = input.slug.trim();
    if
        input.name.trim().is_empty() ||
        input.name.len() > 120 ||
        slug.len() < 2 ||
        slug.len() > 60 ||
        !slug.bytes().all(|b| (b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) ||
        slug.starts_with('-') ||
        slug.ends_with('-')
    {
        return Err(
            ApiError::BadRequest(
                "name is required and slug must be 2–60 lowercase letters, digits, or hyphens".into()
            )
        );
    }
    let id = Uuid::new_v4();
    let tenant = sqlx
        ::query_as::<_, Tenant>(
            "INSERT INTO tenants(id,name,slug) VALUES($1,$2,$3) RETURNING id,name,slug,created_at"
        )
        .bind(id)
        .bind(input.name.trim())
        .bind(slug)
        .fetch_one(&state.db).await?;
    let key = new_api_key();
    sqlx
        ::query("INSERT INTO tenant_api_keys(tenant_id,name,key_hash) VALUES($1,'initial',$2)")
        .bind(id)
        .bind(hash_api_key(&key))
        .execute(&state.db).await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"tenant":tenant,"api_key":key,"warning":"Save this key now; it is shown only once."})
        ),
    ))
}

async fn rotate_tenant_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<Uuid>
) -> Result<Json<Value>, ApiError> {
    require_platform(&headers, &state)?;
    let exists: bool = sqlx
        ::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let mut tx = state.db.begin().await?;
    sqlx
        ::query("UPDATE tenant_api_keys SET active=false WHERE tenant_id=$1")
        .bind(tenant_id)
        .execute(&mut *tx).await?;
    let key = new_api_key();
    sqlx
        ::query("INSERT INTO tenant_api_keys(tenant_id,name,key_hash) VALUES($1,'rotated',$2)")
        .bind(tenant_id)
        .bind(hash_api_key(&key))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(
        Json(
            json!({"tenant_id":tenant_id,"api_key":key,"warning":"Previous tenant keys were disabled. Save this key now; it is shown only once."})
        )
    )
}

async fn list_tenant_keys_for_product_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<Uuid>
) -> Result<Json<Value>, ApiError> {
    require_platform(&headers, &state)?;
    let tenant_exists: bool = sqlx
        ::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    if !tenant_exists {
        return Err(ApiError::NotFound);
    }
    let rows = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "SELECT id,name,role,active AND (expires_at IS NULL OR expires_at>now()) AS active,created_at,last_used_at,expires_at FROM tenant_api_keys WHERE tenant_id=$1 ORDER BY created_at"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"api_keys":rows})))
}

async fn update_tenant_key_for_product_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<UpdateTenantKey>
) -> Result<Json<Value>, ApiError> {
    require_platform(&headers, &state)?;
    validate_key_expiration(input.expires_at)?;
    let row = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "UPDATE tenant_api_keys SET expires_at=$3 WHERE id=$1 AND tenant_id=$2 RETURNING id,name,role,active AND (expires_at IS NULL OR expires_at>now()) AS active,created_at,last_used_at,expires_at"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.expires_at)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({"api_key":row})))
}

async fn rotate_tenant_key_for_product_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, id)): Path<(Uuid, Uuid)>
) -> Result<Json<Value>, ApiError> {
    require_platform(&headers, &state)?;
    let existing = sqlx
        ::query_as::<_, (String, String, bool, Option<DateTime<Utc>>)>(
            "SELECT name,role,active,expires_at FROM tenant_api_keys WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    if !existing.2 || existing.3.as_ref().is_some_and(|expires| *expires <= Utc::now()) {
        return Err(ApiError::BadRequest("an inactive or expired key cannot be rotated".into()));
    }
    let replacement = new_api_key();
    let mut tx = state.db.begin().await?;
    sqlx
        ::query("UPDATE tenant_api_keys SET active=false WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx).await?;
    let row = sqlx
        ::query_as::<_, TenantKeyInfo>(
            "INSERT INTO tenant_api_keys(tenant_id,name,key_hash,role,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id,name,role,active,created_at,last_used_at,expires_at"
        )
        .bind(tenant_id)
        .bind(existing.0)
        .bind(hash_api_key(&replacement))
        .bind(existing.1)
        .bind(existing.3)
        .fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(
        Json(
            json!({"api_key":row,"secret":replacement,"warning":"The previous key is revoked. Save this replacement secret now; it is shown only once."})
        )
    )
}

async fn revoke_tenant_key_for_product_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, id)): Path<(Uuid, Uuid)>
) -> Result<StatusCode, ApiError> {
    require_platform(&headers, &state)?;
    let key = sqlx
        ::query_as::<_, (String, bool)>(
            "SELECT role,active AND (expires_at IS NULL OR expires_at>now()) FROM tenant_api_keys WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    if key.0 == "owner" && key.1 {
        let owners: i64 = sqlx
            ::query_scalar(
                "SELECT count(*) FROM tenant_api_keys WHERE tenant_id=$1 AND active AND role='owner' AND (expires_at IS NULL OR expires_at>now()) AND id<>$2"
            )
            .bind(tenant_id)
            .bind(id)
            .fetch_one(&state.db).await?;
        if owners == 0 {
            return Err(
                ApiError::BadRequest("a tenant must retain at least one active owner key".into())
            );
        }
    }
    sqlx
        ::query("UPDATE tenant_api_keys SET active=false WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
struct TenantIntegration {
    id: Uuid,
    tenant_id: Uuid,
    connector_key: String,
    name: String,
    enabled: bool,
    configuration: Value,
    credential_reference: Option<String>,
    validation_status: String,
    last_validated_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}
#[derive(Deserialize)]
struct TenantIntegrationInput {
    connector_key: String,
    name: String,
    #[serde(default = "default_true")] enabled: bool,
    #[serde(default = "empty_object")] configuration: Value,
    #[serde(default)] credential_reference: Option<String>,
}
fn empty_object() -> Value {
    json!({})
}

/// Validates a connection and returns the configuration to store, with connector defaults filled in.
/// Only inbound connections are supported; outbound connector keys from earlier releases are rejected.
fn validate_integration_input(input: &TenantIntegrationInput) -> Result<Value, ApiError> {
    if input.name.trim().is_empty() || input.name.trim().len() > 120 {
        return Err(
            ApiError::BadRequest(
                "connection name is required and must be at most 120 characters".into()
            )
        );
    }
    if connectors::LEGACY_OUTBOUND.contains(&input.connector_key.as_str()) {
        return Err(
            ApiError::BadRequest(
                "outbound connections are not supported yet; only inbound connections can be created or changed. Configure outbound notification channels under Users & channels".into()
            )
        );
    }
    let connector = connectors
        ::find(&input.connector_key)
        .ok_or_else(|| ApiError::BadRequest("unknown connector key".into()))?;
    if !input.configuration.is_object() {
        return Err(ApiError::BadRequest("configuration must be a JSON object".into()));
    }
    if input.credential_reference.as_ref().is_some_and(|v| (v.len() > 512 || v.trim().is_empty())) {
        return Err(
            ApiError::BadRequest(
                "credential_reference must be non-empty and at most 512 characters".into()
            )
        );
    }
    let configuration = connectors
        ::normalize_configuration(connector, &input.configuration)
        .map_err(ApiError::BadRequest)?;
    if let Some(fields) = configuration.get("payload_fields") {
        let fields = fields
            .as_array()
            .ok_or_else(|| ApiError::BadRequest("payload_fields must be an array".into()))?;
        if fields.len() > 50 {
            return Err(
                ApiError::BadRequest("payload_fields may contain at most 50 entries".into())
            );
        }
        let mut seen: Vec<String> = Vec::new();
        let mut seen_targets: Vec<&str> = Vec::new();
        for field in fields {
            let path = field
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::BadRequest("each payload field requires a path".into()))?;
            if
                path.trim().is_empty() ||
                path.len() > 200 ||
                !path
                    .split('.')
                    .all(
                        |part|
                            !part.is_empty() &&
                            part
                                .bytes()
                                .all(|b| (b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
                    )
            {
                return Err(
                    ApiError::BadRequest(
                        "payload field paths must use dot-separated letters, digits, underscores, or hyphens (max 200 characters)".into()
                    )
                );
            }
            let maps_to = field
                .get("maps_to")
                .map(|v|
                    v
                        .as_str()
                        .ok_or_else(||
                            ApiError::BadRequest("payload field maps_to must be text".into())
                        )
                )
                .transpose()?
                .unwrap_or("");
            if !maps_to.is_empty() && !connectors::MAPS_TO.contains(&maps_to) {
                return Err(
                    ApiError::BadRequest(
                        "payload field maps_to must be dedup_key, title, description, severity, service, status, or url".into()
                    )
                );
            }
            if !maps_to.is_empty() && seen_targets.contains(&maps_to) {
                return Err(
                    ApiError::BadRequest(format!("only one payload field can feed {maps_to}"))
                );
            }
            if !maps_to.is_empty() {
                seen_targets.push(maps_to);
            }
            let identity = format!("{path}>{maps_to}");
            if seen.contains(&identity) {
                return Err(ApiError::BadRequest("payload field paths must be unique".into()));
            }
            seen.push(identity);
            let field_type = field
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::BadRequest("each payload field requires a type".into()))?;
            if !["string", "number", "boolean", "object", "array"].contains(&field_type) {
                return Err(
                    ApiError::BadRequest(
                        "payload field type must be string, number, boolean, object, or array".into()
                    )
                );
            }
            if field.get("required").is_some_and(|v| !v.is_boolean()) {
                return Err(ApiError::BadRequest("payload field required must be boolean".into()));
            }
            if field.get("description").is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 300)) {
                return Err(
                    ApiError::BadRequest(
                        "payload field description must be text of at most 300 characters".into()
                    )
                );
            }
        }
    }
    let forbidden = [
        "password",
        "token",
        "secret",
        "api_key",
        "apikey",
        "client_secret",
        "access_key",
    ];
    if let Some(values) = configuration.as_object() {
        for key in values.keys() {
            let normalized = key.to_ascii_lowercase();
            if forbidden.iter().any(|word| normalized.contains(word)) {
                return Err(
                    ApiError::BadRequest(
                        "do not submit credentials or secret values; use a secret-manager credential_reference".into()
                    )
                );
            }
        }
    }
    Ok(configuration)
}

async fn integration_catalog(headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_role(&headers, &["owner", "admin"])?;
    Ok(Json(json!({"direction":"inbound","connectors":connectors::catalog()})))
}

async fn list_integrations(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let rows = sqlx
        ::query_as::<_, TenantIntegration>(
            "SELECT id,tenant_id,connector_key,name,enabled,configuration,credential_reference,validation_status,last_validated_at,created_at,updated_at FROM tenant_integrations WHERE tenant_id=$1 ORDER BY name"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"integrations":rows})))
}

async fn create_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TenantIntegrationInput>
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let configuration = validate_integration_input(&input)?;
    let row = sqlx
        ::query_as::<_, TenantIntegration>(
            "INSERT INTO tenant_integrations(tenant_id,connector_key,name,enabled,configuration,credential_reference) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,tenant_id,connector_key,name,enabled,configuration,credential_reference,validation_status,last_validated_at,created_at,updated_at"
        )
        .bind(tenant_id)
        .bind(input.connector_key)
        .bind(input.name.trim())
        .bind(input.enabled)
        .bind(configuration)
        .bind(input.credential_reference)
        .fetch_one(&state.db).await?;
    Ok((StatusCode::CREATED, Json(json!({"integration":row}))))
}

async fn update_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<TenantIntegrationInput>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let configuration = validate_integration_input(&input)?;
    let row = sqlx
        ::query_as::<_, TenantIntegration>(
            "UPDATE tenant_integrations SET connector_key=$3,name=$4,enabled=$5,configuration=$6,credential_reference=$7,validation_status='not_validated',last_validated_at=NULL,updated_at=now() WHERE id=$1 AND tenant_id=$2 RETURNING id,tenant_id,connector_key,name,enabled,configuration,credential_reference,validation_status,last_validated_at,created_at,updated_at"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.connector_key)
        .bind(input.name.trim())
        .bind(input.enabled)
        .bind(configuration)
        .bind(input.credential_reference)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({"integration":row})))
}

async fn delete_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<StatusCode, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let result = sqlx
        ::query("DELETE FROM tenant_integrations WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn validate_integration_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin"])?;
    let row = sqlx
        ::query_as::<_, TenantIntegration>(
            "SELECT id,tenant_id,connector_key,name,enabled,configuration,credential_reference,validation_status,last_validated_at,created_at,updated_at FROM tenant_integrations WHERE id=$1 AND tenant_id=$2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.db).await?
        .ok_or(ApiError::NotFound)?;
    let input = TenantIntegrationInput {
        connector_key: row.connector_key.clone(),
        name: row.name,
        enabled: row.enabled,
        configuration: row.configuration,
        credential_reference: row.credential_reference,
    };
    validate_integration_input(&input)?;
    let updated = sqlx
        ::query_as::<_, TenantIntegration>(
            "UPDATE tenant_integrations SET validation_status='valid',last_validated_at=now(),updated_at=now() WHERE id=$1 AND tenant_id=$2 RETURNING id,tenant_id,connector_key,name,enabled,configuration,credential_reference,validation_status,last_validated_at,created_at,updated_at"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    let supported = connectors::find(&updated.connector_key).is_some_and(|c| c.supported);
    Ok(
        Json(
            json!({"integration":updated,"validation_scope":"configuration_only","provider_adapter_available":supported})
        )
    )
}

async fn seed_product_owner(db: &PgPool, tenant_id: Uuid) -> Result<(), ApiError> {
    let email = env::var("PRODUCT_OWNER_EMAIL").unwrap_or_else(|_| "owner@relayops.local".into());
    let password = env
        ::var("PRODUCT_OWNER_PASSWORD")
        .unwrap_or_else(|_| "RelayOps-Owner-2026!".into());
    let existing: Option<bool> = sqlx
        ::query_scalar(
            "SELECT is_product_owner FROM tenant_users WHERE tenant_id=$1 AND lower(email)=lower($2)"
        )
        .bind(tenant_id)
        .bind(email.trim())
        .fetch_optional(db).await?;
    match existing {
        None => {
            valid_login_input(&email, "RelayOps Product Owner", &password)?;
            let hash = make_password_hash(password).await?;
            sqlx
                ::query(
                    "INSERT INTO tenant_users(tenant_id,email,display_name,password_hash,role,is_product_owner) VALUES($1,$2,'RelayOps Product Owner',$3,'owner',true) ON CONFLICT DO NOTHING"
                )
                .bind(tenant_id)
                .bind(email.trim().to_ascii_lowercase())
                .bind(hash)
                .execute(db).await?;
        }
        Some(false) => {
            // On the first upgrade, replace the pre-product-owner account password
            // once so the configured bootstrap credentials reliably work.
            valid_login_input(&email, "RelayOps Product Owner", &password)?;
            let hash = make_password_hash(password).await?;
            sqlx
                ::query(
                    "UPDATE tenant_users SET password_hash=$3,role='owner',is_product_owner=true,failed_login_attempts=0,locked_until=NULL,updated_at=now() WHERE tenant_id=$1 AND lower(email)=lower($2)"
                )
                .bind(tenant_id)
                .bind(email.trim())
                .bind(hash)
                .execute(db).await?;
        }
        Some(true) => {
            sqlx
                ::query(
                    "UPDATE tenant_users SET role='owner' WHERE tenant_id=$1 AND lower(email)=lower($2) AND role<>'owner'"
                )
                .bind(tenant_id)
                .bind(email.trim())
                .execute(db).await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber
        ::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "relayops=info,tower_http=info".into())
        )
        .init();
    let database_url = env::var("DATABASE_URL")?;
    let api_key = env::var("API_KEY")?;
    if api_key.len() < 24 {
        return Err("API_KEY must be at least 24 characters".into());
    }
    let db = PgPoolOptions::new().max_connections(20).connect(&database_url).await?;
    sqlx::migrate!().run(&db).await?;
    let default_tenant_id = sqlx
        ::query_scalar::<_, Uuid>("SELECT id FROM tenants WHERE slug='default'")
        .fetch_one(&db).await?;
    seed_product_owner(&db, default_tenant_id).await?;
    let _notification_worker = tokio::spawn(notifications::run_worker(db.clone()));
    let state = AppState { db, api_key: Arc::new(api_key), default_tenant_id };
    let app = routes::router(state);
    let _frontend_origin = env
        ::var("FRONTEND_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".into());
    let cors = CorsLayer::new()
        .allow_origin(_frontend_origin.parse::<HeaderValue>()?)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let app = app.layer(cors);
    let addr: SocketAddr = env
        ::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "RelayOps API listening");
    axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    }).await?;
    Ok(())
}
