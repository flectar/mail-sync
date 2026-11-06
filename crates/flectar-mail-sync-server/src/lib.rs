//! Flectar Mail Sync server.
//!
//! A blind, end-to-end encrypted record store: it orders and stores
//! ciphertext for groups of devices and never holds a key that could read
//! it. See `docs/SPEC.md` for the protocol.

pub mod api;
pub mod config;
pub mod error;
pub mod events;
pub mod sessions;
pub mod store;

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request};
use axum::routing::{get, post};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub use config::Config;
pub use events::Events;
pub use sessions::Sessions;
pub use store::Store;

/// Shared state of the handlers.
#[derive(Debug)]
pub struct State {
    pub config: Config,
    pub store: Store,
    pub sessions: Sessions,
    pub events: Events,
}

pub type AppState = Arc<State>;

impl State {
    pub fn new(config: Config, store: Store) -> AppState {
        let sessions = Sessions::new(millis(config.challenge_ttl), millis(config.session_ttl));
        Arc::new(Self {
            config,
            store,
            sessions,
            events: Events::default(),
        })
    }
}

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(millis)
        .unwrap_or(0)
}

/// The HTTP application.
pub fn app(state: AppState) -> Router {
    let body_limit = usize::try_from(state.config.limits.max_request_bytes).unwrap_or(usize::MAX);
    Router::new()
        .route("/v1/info", get(api::info))
        .route("/v1/groups", post(api::create_group))
        .route("/v1/auth/challenge", post(api::challenge))
        .route("/v1/auth/session", post(api::session))
        .route("/v1/groups/{group}/commit", post(api::commit))
        .route("/v1/groups/{group}/changes", get(api::changes))
        .route("/v1/groups/{group}/events", get(api::events))
        .route("/healthz", get(api::healthz))
        .layer(DefaultBodyLimit::max(body_limit))
        // Limits the time until response headers; event streams are not cut.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(
            // Log the route template, never the raw path: group ids stay out
            // of the logs.
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                let route = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map_or("unmatched", MatchedPath::as_str);
                tracing::info_span!("request", method = %request.method(), route)
            }),
        )
        .with_state(state)
}

/// Periodic housekeeping: expire sessions and drop old tombstones.
pub async fn run_maintenance(state: AppState) {
    let mut ticks = tokio::time::interval(Duration::from_secs(60));
    let mut minutes = 0u64;
    loop {
        ticks.tick().await;
        let now = now_ms();
        state.sessions.prune(now);
        if minutes.is_multiple_of(60) {
            let cutoff = now - millis(state.config.tombstone_retention);
            match state.store.purge_tombstones(cutoff).await {
                Ok(0) => {}
                Ok(purged) => tracing::info!(purged, "dropped old tombstones"),
                Err(error) => tracing::error!(%error, "tombstone purge failed"),
            }
        }
        minutes += 1;
    }
}
