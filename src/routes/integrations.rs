use axum::{routing::{get, post, put}, Router};
use crate::{create_integration, delete_integration, integration_catalog, list_integrations, update_integration, validate_integration_record, AppState};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/integration-catalog", get(integration_catalog))
        .route("/v1/integrations", get(list_integrations).post(create_integration))
        .route("/v1/integrations/:id", put(update_integration).delete(delete_integration))
        .route("/v1/integrations/:id/validate", post(validate_integration_record))
}
