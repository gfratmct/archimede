//! Forecasting: Timestral sidecar bridge, ONNX (optional), and fast Rust baseline.

mod baseline;
mod onnx;
mod sidecar;

pub use baseline::BaselineForecaster;
pub use onnx::OnnxForecaster;
pub use sidecar::TimestralSidecar;

use anyhow::Result;
use archimede_core::Config;
use archimede_features::FeatureBucket;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastResult {
    pub metric: String,
    pub predicted: Vec<f32>,
    pub lower: Vec<f32>,
    pub upper: Vec<f32>,
    pub source: String,
}

pub struct ForecastEngine {
    baseline: BaselineForecaster,
    sidecar: Option<TimestralSidecar>,
    onnx: Option<OnnxForecaster>,
    horizon: usize,
    context_len: usize,
}

impl ForecastEngine {
    pub fn from_config(cfg: &Config) -> Self {
        let sidecar = cfg
            .forecast
            .sidecar_url
            .as_ref()
            .map(|u| TimestralSidecar::new(u, &cfg.forecast.model_size));
        let onnx = cfg
            .forecast
            .onnx_path
            .as_ref()
            .and_then(|p| match OnnxForecaster::load(p) {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::warn!(error = %e, "ONNX forecaster not loaded");
                    None
                }
            });
        Self {
            baseline: BaselineForecaster::new(cfg.forecast.horizon),
            sidecar,
            onnx,
            horizon: cfg.forecast.horizon,
            context_len: cfg.forecast.context_len,
        }
    }

    pub async fn forecast_metric(
        &self,
        metric: &str,
        history: &[f64],
    ) -> Result<ForecastResult> {
        let hist: Vec<f64> = history
            .iter()
            .copied()
            .rev()
            .take(self.context_len)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        if let Some(onnx) = &self.onnx {
            if let Ok(r) = onnx.forecast(metric, &hist, self.horizon) {
                return Ok(r);
            }
        }
        if let Some(side) = &self.sidecar {
            if let Ok(r) = side.forecast(metric, &hist, self.horizon).await {
                return Ok(r);
            }
        }
        Ok(self.baseline.forecast(metric, &hist))
    }

    pub async fn forecast_buckets(
        &self,
        buckets: &[FeatureBucket],
        metrics: &[&str],
    ) -> Result<Vec<ForecastResult>> {
        let mut out = Vec::new();
        for metric in metrics {
            let series: Vec<f64> = buckets
                .iter()
                .map(|b| *b.metric_map().get(*metric).unwrap_or(&0.0))
                .collect();
            out.push(self.forecast_metric(metric, &series).await?);
        }
        Ok(out)
    }
}
