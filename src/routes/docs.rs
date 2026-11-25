use axum::{http::header, response::{Html, IntoResponse}, routing::get, Router};
use crate::AppState;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/docs", get(swagger_ui))
        .route("/docs/", get(swagger_ui))
        .route("/openapi.yaml", get(openapi_yaml))
}

async fn swagger_ui() -> Html<&'static str> {
    Html(include_str!("../../docs/swagger.html"))
}

async fn openapi_yaml() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/yaml; charset=utf-8")], include_str!("../../docs/openapi.yaml"))
}
