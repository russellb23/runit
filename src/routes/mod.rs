use axum::{middleware, routing::get, Router};
use crate::{authenticate, health, AppState};

mod analysis;
mod auth;
mod escalations;
mod docs;
mod incidents;
mod integrations;
mod notifications;
mod schedules;
mod tenants;

/// Compose feature routers into the single authenticated API process.
pub(super) fn router(state: AppState) -> Router {
    let api = Router::new()
        .merge(incidents::router())
        .merge(analysis::router())
        .merge(auth::protected_router())
        .merge(escalations::router())
        .merge(integrations::router())
        .merge(notifications::router())
        .merge(schedules::router())
        .merge(tenants::router())
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state.clone());

    Router::new().route("/healthz", get(health)).merge(auth::public_router().with_state(state.clone())).merge(docs::router().with_state(state.clone())).merge(api)
}
