use anyhow::Result;
use archimede_core::{Config, Store};
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<Store>>,
    cfg: Arc<Config>,
}

pub async fn serve(cfg: Arc<Config>, store: Arc<Mutex<Store>>) -> Result<()> {
    let state = AppState {
        store,
        cfg: cfg.clone(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/stats", get(stats))
        .route("/v1/logs", get(logs))
        .route("/v1/alerts", get(alerts))
        .route("/v1/metrics", get(metrics))
        .route("/v1/config", get(config_view))
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

struct ApiError(anyhow::Error);

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        axum::response::IntoResponse::into_response((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": self.0.to_string()})),
        ))
    }
}
