//! Server-rendered web UI — maud pages + htmx partials + SSE streams.
//! The JSON `/api/*` and `/ws` seam stays for other shells; this module
//! only owns the HTML surface.

pub(crate) mod components;
pub(crate) mod layout;
mod pages;
mod partials;
mod report;
mod sse;

use std::sync::Arc;

use axum::{
    Router,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use maud::Markup;

use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(root))
        .route("/scan", get(|| page("scan")))
        .route("/sniff", get(|| page("sniff")))
        .route("/wifi", get(|| page("wifi")))
        .route("/analyze", get(|| page("analyze")))
        .route("/tools", get(|| page("tools")))
        .route("/devices", get(|| page("devices")))
        .merge(partials::router())
        .merge(sse::router())
}

async fn root() -> Redirect {
    Redirect::to("/scan")
}

async fn page(view: &'static str) -> Response {
    let (actions, body): (Markup, Markup) = match view {
        "sniff" => pages::sniff(),
        "wifi" => pages::wifi(),
        "analyze" => pages::analyze(),
        "tools" => pages::tools(),
        "devices" => pages::devices(),
        _ => pages::scan(),
    };
    layout::shell(view, layout::main_region(view, actions, body)).into_response()
}
