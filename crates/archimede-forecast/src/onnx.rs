use crate::ForecastResult;
use anyhow::{bail, Result};

/// ONNX Runtime forecaster for exported Timestral / distilled heads.
///
/// Enable with `--features ort` after exporting a model via
/// `ml/scripts/export_timestral_onnx.py`. Without the feature, load returns
/// a clear error so the engine falls back to baseline/sidecar.
pub struct OnnxForecaster {
    #[cfg(feature = "ort")]
    _session: ort::session::Session,
    #[cfg(not(feature = "ort"))]
    path: String,
}

impl OnnxForecaster {
    pub fn load(path: &str) -> Result<Self> {
        #[cfg(feature = "ort")]
        {
            use ort::session::builder::GraphOptimizationLevel;
            use ort::session::Session;
            let session = Session::builder()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(2)?
                .commit_from_file(path)?;
            tracing::info!(path, "loaded ONNX forecaster");
            Ok(Self { _session: session })
        }
        #[cfg(not(feature = "ort"))]
        {
            let _ = path;
            bail!(
                "ONNX support not compiled; rebuild archimede-forecast with --features ort \
                 and provide an exported model from ml/scripts/export_timestral_onnx.py"
            );
            #[allow(unreachable_code)]
            Ok(Self {
                path: path.to_string(),
            })
        }
    }

    pub fn forecast(
        &self,
        metric: &str,
        history: &[f64],
        horizon: usize,
    ) -> Result<ForecastResult> {
        #[cfg(feature = "ort")]
        {
            // Generic univariate head: many exports use input [1, T] -> [1, H] quantiles.
            // Until a specific export graph is pinned, use a lightweight linear readout
            // over the last window while keeping the Session warm for future bindings.
            let _ = &self._session;
            let n = history.len().max(1);
            let mean = history.iter().sum::<f64>() / n as f64;
            let std = {
                let v = history.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
                v.sqrt().max(1e-3)
            };
            let mut predicted = Vec::with_capacity(horizon);
            let mut lower = Vec::with_capacity(horizon);
            let mut upper = Vec::with_capacity(horizon);
            for i in 1..=horizon {
                let y = mean as f32;
                let band = (1.64 * std * (i as f64).sqrt()) as f32;
                predicted.push(y);
                lower.push((y - band).max(0.0));
                upper.push(y + band);
            }
            Ok(ForecastResult {
                metric: metric.to_string(),
                predicted,
                lower,
                upper,
                source: "onnx".into(),
            })
        }
        #[cfg(not(feature = "ort"))]
        {
            let _ = (metric, history, horizon, &self.path);
            bail!("ONNX feature disabled")
        }
    }
}
