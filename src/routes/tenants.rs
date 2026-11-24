use axum::{routing::{delete, get, post, put}, Router};
use crate::{create_tenant, create_tenant_key, current_tenant, list_tenant_keys, list_tenant_keys_for_product_owner, list_tenants, revoke_tenant_key, revoke_tenant_key_for_product_owner, rotate_individual_tenant_key, rotate_tenant_key, rotate_tenant_key_for_product_owner, update_tenant_key, update_tenant_key_for_product_owner, AppState};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/tenant", get(current_tenant))
        .route("/v1/tenants", get(list_tenants).post(create_tenant))
        .route("/v1/tenants/:tenant_id/rotate-key", post(rotate_tenant_key))
        .route("/v1/tenants/:tenant_id/api-keys", get(list_tenant_keys_for_product_owner))
        .route("/v1/tenants/:tenant_id/api-keys/:id", put(update_tenant_key_for_product_owner).delete(revoke_tenant_key_for_product_owner))
        .route("/v1/tenants/:tenant_id/api-keys/:id/rotate", post(rotate_tenant_key_for_product_owner))
        .route("/v1/api-keys", get(list_tenant_keys).post(create_tenant_key))
        .route("/v1/api-keys/:id", delete(revoke_tenant_key).put(update_tenant_key))
        .route("/v1/api-keys/:id/rotate", post(rotate_individual_tenant_key))
}
