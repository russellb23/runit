use axum::{ routing::{ delete, get, post }, Router };
use crate::{
    auth_me,
    create_login_account,
    list_login_accounts,
    list_login_sessions,
    login,
    logout,
    recover_login,
    revoke_login_session,
    setup_login,
    AppState,
};

pub(super) fn public_router() -> Router<AppState> {
    Router::new().route("/v1/auth/login", post(login))
}

pub(super) fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/setup", post(setup_login))
        .route("/v1/auth/recover", post(recover_login))
        .route("/v1/auth/me", get(auth_me))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/sessions", get(list_login_sessions))
        .route("/v1/auth/sessions/:id", delete(revoke_login_session))
        .route("/v1/auth/accounts", get(list_login_accounts).post(create_login_account))
}
