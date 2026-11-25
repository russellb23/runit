use axum::{routing::{get, put}, Router};
use crate::{create_policy, delete_policy, list_policies, update_policy, AppState};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/escalation-policies", get(list_policies).post(create_policy))
        .route("/v1/escalation-policies/:id", put(update_policy).delete(delete_policy))
}
