//! Flectar Mail Sync server.
//!
//! A blind, end-to-end encrypted record store: it orders and stores
//! ciphertext for groups of devices and never holds a key that could read
//! it. See `docs/SPEC.md` for the protocol.

pub mod api;
pub mod config;
pub mod error;
pub mod events;
pub mod limits;
pub mod pairing;
pub mod sessions;
pub mod store;

use api::Limit;
use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request};
use axum::middleware::from_fn_with_state;
use axum::routing::{MethodRouter, delete, get, post, put};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub use config::Config;
pub use events::Events;
pub use limits::RateLimits;
pub use pairing::Pairing;
pub use sessions::Sessions;
pub use store::Store;

/// Body limit of the endpoints that need no session. Their requests are a
/// few kilobytes; the large limit is only for authenticated commits.
const SMALL_BODY_BYTES: usize = 64 * 1024;

/// Shared state of the handlers.
#[derive(Debug)]
pub struct State {
    pub config: Config,
    pub store: Store,
    pub sessions: Sessions,
    pub events: Events,
    pub pairing: Pairing,
    pub rate_limits: RateLimits,
}

pub type AppState = Arc<State>;

impl State {
    pub fn new(config: Config, store: Store) -> AppState {
        let sessions = Sessions::new(millis(config.challenge_ttl), millis(config.session_ttl));
        let pairing = Pairing::new(config.pairing.clone());
        let rate_limits = RateLimits::new(&config.rates);
        Arc::new(Self {
            config,
            store,
            sessions,
            events: Events::default(),
            pairing,
            rate_limits,
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
    let limited = |limit, route| limited(&state, limit, route);
    Router::new()
        .route("/v1/info", get(api::info))
        .route(
            "/v1/groups",
            limited(Limit::CreateGroup, post(api::create_group)),
        )
        .route(
            "/v1/auth/challenge",
            limited(Limit::Login, post(api::challenge)),
        )
        .route(
            "/v1/auth/session",
            limited(Limit::Login, post(api::session)),
        )
        .route(
            "/v1/pairing",
            limited(Limit::Pairing, post(api::pairing::create)),
        )
        .route(
            "/v1/pairing/codes/{code}",
            limited(Limit::PairingCode, get(api::pairing::resolve_code)),
        )
        .route(
            "/v1/pairing/{slot}",
            limited(Limit::Pairing, delete(api::pairing::delete)),
        )
        .route(
            "/v1/pairing/{slot}/messages",
            limited(Limit::Pairing, get(api::pairing::messages)),
        )
        .route(
            "/v1/pairing/{slot}/messages/{index}",
            limited(Limit::Pairing, put(api::pairing::put_message)),
        )
        .route("/v1/groups/{group}/commit", post(api::commit))
        .route("/v1/groups/{group}/changes", get(api::changes))
        .route("/v1/groups/{group}/events", get(api::events))
        .route("/v1/groups/{group}/ops", get(api::ops).post(api::append_op))
        .route("/v1/groups/{group}/wrap", get(api::wrap))
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

/// An endpoint that needs no session: rate limited per client address, and
/// with a small body limit.
fn limited(
    state: &AppState,
    limit: Limit,
    route: MethodRouter<AppState>,
) -> MethodRouter<AppState> {
    route
        .layer::<_, Infallible>(DefaultBodyLimit::max(SMALL_BODY_BYTES))
        .layer(from_fn_with_state(
            (Arc::clone(state), limit),
            api::limit_by_address,
        ))
}

/// Serve `listener` until `shutdown` resolves. Event streams are then closed,
/// since they never end on their own, and in-flight requests finish.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let events = Arc::clone(&state);
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        events.events.close_all();
    })
    .await
}

/// Periodic housekeeping: expire sessions, pairing slots and rate-limit
/// entries, and drop old tombstones.
pub async fn run_maintenance(state: AppState) {
    let mut ticks = tokio::time::interval(Duration::from_secs(60));
    let mut minutes = 0u64;
    loop {
        ticks.tick().await;
        let now = now_ms();
        state.sessions.prune(now);
        state.events.prune();
        state.pairing.prune(now);
        state.rate_limits.prune(std::time::Instant::now());
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
