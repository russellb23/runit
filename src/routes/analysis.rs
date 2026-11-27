use axum::{routing::get, Json, Router};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{authorized, require_role, ApiError, AppState};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/analytics/incidents", get(incident_analytics))
        .route("/v1/analytics/performance", get(performance))
}

async fn incident_analytics(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM incidents WHERE tenant_id=$1 AND source<>'demo'")
        .bind(tenant_id).fetch_one(&state.db).await?;
    let by_source = sqlx::query_as::<_, (String, i64)>("SELECT COALESCE(NULLIF(source,''),'manual') AS label,count(*)::bigint FROM incidents WHERE tenant_id=$1 AND source<>'demo' GROUP BY label ORDER BY count(*) DESC,label")
        .bind(tenant_id).fetch_all(&state.db).await?;
    let by_user = sqlx::query_as::<_, (String, i64)>("SELECT COALESCE(NULLIF(assignee,''),'Unassigned') AS label,count(*)::bigint FROM incidents WHERE tenant_id=$1 AND source<>'demo' GROUP BY label ORDER BY count(*) DESC,label")
        .bind(tenant_id).fetch_all(&state.db).await?;
    Ok(Json(json!({"total":total,"by_integration":by_source,"by_user":by_user})))
}

#[derive(Deserialize)]
struct PerformanceQuery {
    /// Look-back window in days; omit for all time.
    days: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
struct PerformanceRow {
    name: String,
    handled: i64,
    acknowledged: i64,
    resolved: i64,
    /// Mean turnaround: seconds from a relay being created to its first acknowledgement.
    mtat_seconds: Option<f64>,
    /// Mean time to complete: seconds from a relay being created to its resolution.
    mttr_seconds: Option<f64>,
}

/// Response and completion performance by responder and by team. Relays are attributed to their
/// current assignee (acknowledging a relay assigns it to the acknowledger); demo relays are excluded.
async fn performance(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<PerformanceQuery>) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    require_role(&headers, &["owner", "admin", "responder", "viewer"])?;
    let days = query.days.filter(|d| (1..=3650).contains(d));
    let overall = sqlx::query_as::<_, PerformanceRow>(
        r#"SELECT 'All relays'::text AS name,
                  count(*)::bigint AS handled,
                  count(*) FILTER (WHERE i.acknowledged_at IS NOT NULL)::bigint AS acknowledged,
                  count(*) FILTER (WHERE i.status='resolved')::bigint AS resolved,
                  (avg(EXTRACT(EPOCH FROM (i.acknowledged_at-i.created_at))) FILTER (WHERE i.acknowledged_at IS NOT NULL))::float8 AS mtat_seconds,
                  (avg(EXTRACT(EPOCH FROM (i.resolved_at-i.created_at))) FILTER (WHERE i.status='resolved' AND i.resolved_at IS NOT NULL))::float8 AS mttr_seconds
           FROM incidents i
           WHERE i.tenant_id=$1 AND i.source<>'demo'
             AND ($2::int IS NULL OR i.created_at >= now() - ($2::int * interval '1 day'))"#,
    )
    .bind(tenant_id)
    .bind(days)
    .fetch_one(&state.db)
    .await?;
    let by_user = sqlx::query_as::<_, PerformanceRow>(
        r#"SELECT i.assignee AS name,
                  count(*)::bigint AS handled,
                  count(*) FILTER (WHERE i.acknowledged_at IS NOT NULL)::bigint AS acknowledged,
                  count(*) FILTER (WHERE i.status='resolved')::bigint AS resolved,
                  (avg(EXTRACT(EPOCH FROM (i.acknowledged_at-i.created_at))) FILTER (WHERE i.acknowledged_at IS NOT NULL))::float8 AS mtat_seconds,
                  (avg(EXTRACT(EPOCH FROM (i.resolved_at-i.created_at))) FILTER (WHERE i.status='resolved' AND i.resolved_at IS NOT NULL))::float8 AS mttr_seconds
           FROM incidents i
           WHERE i.tenant_id=$1 AND i.source<>'demo' AND NULLIF(i.assignee,'') IS NOT NULL
             AND ($2::int IS NULL OR i.created_at >= now() - ($2::int * interval '1 day'))
           GROUP BY i.assignee ORDER BY 4 DESC, 1"#,
    )
    .bind(tenant_id)
    .bind(days)
    .fetch_all(&state.db)
    .await?;
    let by_team = sqlx::query_as::<_, PerformanceRow>(
        r#"SELECT t.team AS name,
                  count(*)::bigint AS handled,
                  count(*) FILTER (WHERE i.acknowledged_at IS NOT NULL)::bigint AS acknowledged,
                  count(*) FILTER (WHERE i.status='resolved')::bigint AS resolved,
                  (avg(EXTRACT(EPOCH FROM (i.acknowledged_at-i.created_at))) FILTER (WHERE i.acknowledged_at IS NOT NULL))::float8 AS mtat_seconds,
                  (avg(EXTRACT(EPOCH FROM (i.resolved_at-i.created_at))) FILTER (WHERE i.status='resolved' AND i.resolved_at IS NOT NULL))::float8 AS mttr_seconds
           FROM incidents i
           JOIN LATERAL (
               SELECT DISTINCT x.t AS team
               FROM notification_recipients r CROSS JOIN LATERAL unnest(r.groups || ARRAY[r.team]) AS x(t)
               WHERE r.tenant_id=$1 AND r.handle=i.assignee AND btrim(x.t)<>''
           ) t ON true
           WHERE i.tenant_id=$1 AND i.source<>'demo' AND NULLIF(i.assignee,'') IS NOT NULL
             AND ($2::int IS NULL OR i.created_at >= now() - ($2::int * interval '1 day'))
           GROUP BY t.team ORDER BY 4 DESC, 1"#,
    )
    .bind(tenant_id)
    .bind(days)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "days": days, "overall": overall, "by_user": by_user, "by_team": by_team })))
}
