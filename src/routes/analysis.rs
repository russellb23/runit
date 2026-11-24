use axum::{ routing::get, Json, Router };
use axum::extract::State;
use axum::http::HeaderMap;
use serde_json::{ json, Value };
use crate::{ authorized, ApiError, AppState };

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/v1/analytics/incidents", get(incident_analytics))
}

async fn incident_analytics(
    State(state): State<AppState>,
    headers: HeaderMap
) -> Result<Json<Value>, ApiError> {
    let tenant_id = authorized(&headers, &state.api_key)?;
    let total: i64 = sqlx
        ::query_scalar("SELECT count(*)::bigint FROM incidents WHERE tenant_id=$1")
        .bind(tenant_id)
        .fetch_one(&state.db).await?;
    let by_source = sqlx
        ::query_as::<_, (String, i64)>(
            "SELECT COALESCE(NULLIF(source,''),'manual') AS label,count(*)::bigint FROM incidents WHERE tenant_id=$1 GROUP BY label ORDER BY count(*) DESC,label"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    let by_user = sqlx
        ::query_as::<_, (String, i64)>(
            "SELECT COALESCE(NULLIF(assignee,''),'Unassigned') AS label,count(*)::bigint FROM incidents WHERE tenant_id=$1 GROUP BY label ORDER BY count(*) DESC,label"
        )
        .bind(tenant_id)
        .fetch_all(&state.db).await?;
    Ok(Json(json!({"total":total,"by_integration":by_source,"by_user":by_user})))
}
