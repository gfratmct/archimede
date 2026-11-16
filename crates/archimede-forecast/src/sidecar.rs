use crate::ForecastResult;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::time::Duration;

/// HTTP client for a local Timestral Python sidecar (`ml/scripts/serve_timestral.py`).
pub struct TimestralSidecar {
    http: reqwest::Client,
    url: String,
    model_size: String,
}

impl TimestralSidecar {
    pub fn new(url: &str, model_size: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest");
        Self {
            http,
            url: url.trim_end_matches('/').to_string(),
            model_size: model_size.to_string(),
        }
    }

    pub async fn forecast(
        &self,
        metric: &str,
        history: &[f64],
        horizon: usize,
    ) -> Result<ForecastResult> {
        #[derive(Deserialize)]
        struct Resp {
            predicted: Vec<f32>,
            lower: Vec<f32>,
            upper: Vec<f32>,
        }

        let endpoint = format!("{}/v1/forecast", self.url);
        let body = serde_json::json!({
            "model_size": self.model_size,
            "metric": metric,
            "history": history,
            "horizon": horizon,
        });
        let resp = self
            .http
            .post(&endpoint)
            .json(&body)
            .send()
            .await
            .context("timestral sidecar request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("sidecar status {}", resp.status()));
        }
        let parsed: Resp = resp.json().await.context("sidecar json")?;
        Ok(ForecastResult {
            metric: metric.to_string(),
            predicted: parsed.predicted,
            lower: parsed.lower,
            upper: parsed.upper,
            source: format!("timestral-{}", self.model_size),
        })
    }
}
