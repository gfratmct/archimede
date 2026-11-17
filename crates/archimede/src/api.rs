use anyhow::Result;
use archimede_core::{
    Config, Event, EventBus, EventKind, SpanRecord, Store, TraceRecord,
};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<Store>>,
    cfg: Arc<Config>,
    bus: EventBus,
}

pub async fn serve(
    cfg: Arc<Config>,
    store: Arc<Mutex<Store>>,
    bus: EventBus,
) -> Result<()> {
    let state = AppState {
        store,
        cfg: cfg.clone(),
        bus,
    };
    let app = Router::new()
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
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cfg.daemon.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "API listening");
    axum::serve(listener, app).await?;
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
    Json(serde_json::to_value(state.cfg.as_ref()).unwrap_or_default())
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
    Json(body): Json<CreateTraceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
    Json(body): Json<SpansBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let spans = match body {
        SpansBody::One(s) => vec![s],
        SpansBody::Many { spans } => spans,
    };
    let mut accepted = 0usize;
    for span in spans {
        // Daemon consumer persists + runs policy; API only publishes.
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

struct ApiError {
    status: axum::http::StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
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
