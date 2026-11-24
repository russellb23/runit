use axum::{ routing::{ get, put }, Router };
use crate::{ create_schedule, delete_schedule, list_schedules, update_schedule, AppState };

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/schedules", get(list_schedules).post(create_schedule))
        .route("/v1/schedules/:id", put(update_schedule).delete(delete_schedule))
}
