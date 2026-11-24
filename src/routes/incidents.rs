use axum::{ routing::{ get, post }, Router };
use crate::{ acknowledge, create_alert, events, get_incident, list_incidents, resolve, AppState };

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/alerts", post(create_alert))
        .route("/v1/incidents", get(list_incidents))
        .route("/v1/incidents/:id", get(get_incident))
        .route("/v1/incidents/:id/acknowledge", post(acknowledge))
        .route("/v1/incidents/:id/resolve", post(resolve))
        .route("/v1/incidents/:id/events", get(events))
}
