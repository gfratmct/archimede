use anyhow::Result;
use archimede_core::{
    Config, Event, EventBus, EventKind, SpanRecord, Store, TraceRecord,
};
use archimede_policy::PolicyEngine;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<Store>>,
    cfg: Arc<Config>,
    bus: EventBus,
    policy: Arc<PolicyEngine>,
}

pub async fn serve(
    cfg: Arc<Config>,
    store: Arc<Mutex<Store>>,
    bus: EventBus,
    policy: Arc<PolicyEngine>,
) -> Result<()> {
    let state = AppState {
        store,
        cfg: cfg.clone(),
        bus,
        policy,
    };
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/v1/stats", get(stats))
        .route("/v1/logs", get(logs))
        .route("/v1/alerts", get(alerts))
        .route("/v1/metrics", get(metrics))
        .route("/v1/config", get(config_view))
        .route("/v1/traces", post(create_trace).get(list_traces))
        .route("/v1/traces/{id}", get(get_trace))
        .route("/v1/spans", post(ingest_spans))
        .route("/v1/flags", get(list_flags))
        .route("/v1/enforcement", get(list_enforcement))
        .route("/v1/clear", post(clear_alerts_and_flags))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    if let Some(dir) = cfg.expand_dashboard_dir() {
        let index = dir.join("index.html");
        tracing::info!(path = %dir.display(), "serving dashboard");
        let spa = ServeDir::new(dir).not_found_service(ServeFile::new(index));
        app = app.fallback_service(spa);
    } else {
        tracing::info!("dashboard_dir unset or missing index.html; API-only mode");
    }

    let addr: SocketAddr = cfg.daemon.bind.parse()?;
    if !is_loopback_bind(&cfg.daemon.bind) && cfg.daemon.api_token.as_ref().map(|t| t.is_empty()).unwrap_or(true) {
        tracing::warn!(
            bind = %cfg.daemon.bind,
            "daemon binds non-loopback without api_token; mutating routes are unprotected"
        );
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "API listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn is_loopback_bind(bind: &str) -> bool {
    bind.starts_with("127.") || bind.starts_with("[::1]") || bind.starts_with("localhost")
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-archimede-token").and_then(|v| v.to_str().ok()) {
        return Some(v.to_string());
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string()))
}

fn require_api_token(cfg: &Config, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(expected) = cfg.daemon.api_token.as_ref().filter(|t| !t.is_empty()) else {
        // No token configured: allow only on loopback binds.
        if is_loopback_bind(&cfg.daemon.bind) {
            return Ok(());
        }
        return Err(ApiError::forbidden(
            "api_token required when daemon.bind is not loopback",
        ));
    };
    match extract_token(headers) {
        Some(got) if got == *expected => Ok(()),
        _ => Err(ApiError::unauthorized(
            "missing or invalid X-Archimede-Token / Bearer token",
        )),
    }
}

/// Mutating ingest is token-gated when enforcement is enabled (prevents
/// unauthenticated span injection that could drive policy actions).
fn require_ingest_auth(cfg: &Config, headers: &HeaderMap) -> Result<(), ApiError> {
    if cfg.enforcement.enabled {
        return require_api_token(cfg, headers);
    }
    // Still require token if configured.
    if cfg
        .daemon
        .api_token
        .as_ref()
        .map(|t| !t.is_empty())
        .unwrap_or(false)
    {
        return require_api_token(cfg, headers);
    }
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "service": "archimede"}))
}

async fn stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let stats = store.stats().map_err(ApiError::from)?;
    Ok(Json(serde_json::to_value(stats).unwrap()))
}

#[derive(Deserialize)]
struct LogsQuery {
    limit: Option<usize>,
    agent: Option<String>,
}

async fn logs(
    State(state): State<AppState>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let events = store
        .recent_events(q.limit.unwrap_or(50), q.agent.as_deref())
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::to_value(events).unwrap()))
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

async fn alerts(
    State(state): State<AppState>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let alerts = store
        .recent_alerts(q.limit.unwrap_or(20))
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::to_value(alerts).unwrap()))
}

#[derive(Deserialize)]
struct MetricsQuery {
    agent: String,
    metric: String,
    limit: Option<usize>,
}

async fn metrics(
    State(state): State<AppState>,
    Query(q): Query<MetricsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let series = store
        .metric_series(&q.agent, &q.metric, q.limit.unwrap_or(256))
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::to_value(series).unwrap()))
}

async fn config_view(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Never expose api_token in the config view.
    let mut v = serde_json::to_value(state.cfg.as_ref()).unwrap_or_default();
    if let Some(obj) = v.get_mut("daemon").and_then(|d| d.as_object_mut()) {
        if obj.contains_key("api_token") {
            obj.insert(
                "api_token".into(),
                serde_json::Value::String("[redacted]".into()),
            );
        }
    }
    Json(v)
}

#[derive(Deserialize)]
struct TracesQuery {
    limit: Option<usize>,
    agent: Option<String>,
}

async fn list_traces(
    State(state): State<AppState>,
    Query(q): Query<TracesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let traces = store
        .recent_traces(q.limit.unwrap_or(50), q.agent.as_deref())
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::to_value(traces).unwrap()))
}

async fn get_trace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    match store.get_trace(&id).map_err(ApiError::from)? {
        Some(tree) => Ok(Json(serde_json::to_value(tree).unwrap())),
        None => Err(ApiError::not_found(format!("trace {id} not found"))),
    }
}

#[derive(Deserialize)]
struct CreateTraceRequest {
    #[serde(default)]
    trace_id: Option<String>,
    name: Option<String>,
    agent: Option<String>,
    harness: Option<String>,
    user_id: Option<String>,
    session_id: Option<String>,
    #[serde(default)]
    metadata: serde_json::Value,
    start_ts: Option<chrono::DateTime<Utc>>,
    end_ts: Option<chrono::DateTime<Utc>>,
}

async fn create_trace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateTraceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_ingest_auth(&state.cfg, &headers)?;
    let trace = TraceRecord {
        trace_id: body
            .trace_id
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        name: body.name,
        agent: body.agent,
        harness: body.harness,
        user_id: body.user_id,
        session_id: body.session_id,
        metadata: if body.metadata.is_null() {
            serde_json::json!({})
        } else {
            body.metadata
        },
        start_ts: body.start_ts.unwrap_or_else(Utc::now),
        end_ts: body.end_ts,
    };
    {
        let store = state.store.lock().await;
        store.upsert_trace(&trace).map_err(ApiError::from)?;
    }
    Ok(Json(serde_json::to_value(trace).unwrap()))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SpansBody {
    One(SpanRecord),
    Many { spans: Vec<SpanRecord> },
}

async fn ingest_spans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SpansBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_ingest_auth(&state.cfg, &headers)?;
    let spans = match body {
        SpansBody::One(s) => vec![s],
        SpansBody::Many { spans } => spans,
    };
    let mut accepted = 0usize;
    for span in spans {
        // Daemon consumer persists + runs policy; API only publishes.
        // Policy never uses client-supplied attrs.pid for process termination.
        let ev = Event::new("harness_sdk", EventKind::Span(span));
        let _ = state.bus.publish(ev);
        accepted += 1;
    }
    Ok(Json(serde_json::json!({"accepted": accepted})))
}

#[derive(Deserialize)]
struct FlagsQuery {
    limit: Option<usize>,
    agent: Option<String>,
    trace_id: Option<String>,
}

async fn list_flags(
    State(state): State<AppState>,
    Query(q): Query<FlagsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let flags = store
        .recent_flags(q.limit.unwrap_or(50), q.agent.as_deref(), q.trace_id.as_deref())
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::to_value(flags).unwrap()))
}

async fn list_enforcement(
    State(state): State<AppState>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let rows = store
        .recent_enforcement(q.limit.unwrap_or(50))
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({
        "enforcement_enabled": state.cfg.enforcement.enabled,
        "actions_allowlist": state.cfg.enforcement.actions,
        "recent": rows,
    })))
}

async fn clear_alerts_and_flags(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Always require token when configured; otherwise loopback-only.
    require_api_token(&state.cfg, &headers)?;
    let (alerts, flags) = {
        let store = state.store.lock().await;
        store.clear_alerts_and_flags().map_err(ApiError::from)?
    };
    state.policy.forget_seen();
    Ok(Json(serde_json::json!({
        "ok": true,
        "cleared_alerts": alerts,
        "cleared_flags": flags,
    })))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }

    fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
        }
    }

    fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: e.to_string(),
        }
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        axum::response::IntoResponse::into_response((
            self.status,
            Json(serde_json::json!({"error": self.message})),
        ))
    }
}
