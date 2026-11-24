use axum::{ routing::{ get, post, put }, Router };
use crate::{
    create_notification_user,
    create_recipient,
    deactivate_notification_user,
    delete_recipient,
    list_deliveries,
    list_notification_users,
    list_recipients,
    retry_delivery,
    update_notification_user,
    update_recipient,
    AppState,
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/notification-recipients", get(list_recipients).post(create_recipient))
        .route("/v1/notification-recipients/:id", put(update_recipient).delete(delete_recipient))
        .route(
            "/v1/notification-users",
            get(list_notification_users).post(create_notification_user)
        )
        .route(
            "/v1/notification-users/:handle",
            put(update_notification_user).delete(deactivate_notification_user)
        )
        .route("/v1/notification-deliveries", get(list_deliveries))
        .route("/v1/notification-deliveries/:id/retry", post(retry_delivery))
}
