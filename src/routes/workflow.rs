use axum::{ routing::{ get, post, put }, Router };

use crate::{ relay_workflow as w, AppState };

/// Assignment, spikes, team leads, responder lookup, and the demo relay.
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/me/responder", get(w::me_responder))
        .route("/v1/responders", get(w::list_responders))
        .route("/v1/team-leads", get(w::list_team_leads))
        .route("/v1/team-leads/:team", put(w::set_team_lead).delete(w::clear_team_lead))
        .route("/v1/incidents/:id/assign", post(w::assign_incident))
        .route("/v1/incidents/:id/spike", post(w::raise_spike))
        .route("/v1/assignment-requests", get(w::list_assignment_requests))
        .route("/v1/assignment-requests/:id/accept", post(w::accept_assignment))
        .route("/v1/assignment-requests/:id/decline", post(w::decline_assignment))
        .route("/v1/spikes", get(w::list_spikes))
        .route("/v1/spikes/:id/resolve", post(w::resolve_spike))
        .route("/v1/demo/relay", post(w::create_demo_relay))
}
