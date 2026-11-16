use crate::ForecastResult;

/// Fast CPU baseline: exponential smoothing + residual band.
/// Used when Timestral sidecar / ONNX are unavailable; also a latency floor for Rust hot path.
pub struct BaselineForecaster {
    horizon: usize,
    alpha: f64,
}

impl BaselineForecaster {
    pub fn new(horizon: usize) -> Self {
        Self {
            horizon,
            alpha: 0.35,
        }
    }

    pub fn forecast(&self, metric: &str, history: &[f64]) -> ForecastResult {
        if history.is_empty() {
            return ForecastResult {
                metric: metric.to_string(),
                predicted: vec![0.0; self.horizon],
                lower: vec![0.0; self.horizon],
                upper: vec![0.0; self.horizon],
                source: "baseline".into(),
            };
        }

        let mut level = history[0];
        for &x in &history[1..] {
            level = self.alpha * x + (1.0 - self.alpha) * level;
        }

        let mean = history.iter().sum::<f64>() / history.len() as f64;
        let var = history
            .iter()
            .map(|x| {
                let d = x - mean;
                d * d
            })
            .sum::<f64>()
            / history.len().max(1) as f64;
        let std = var.sqrt().max(1e-3);

        // Light trend from last window.
        let trend = if history.len() >= 4 {
            let n = history.len();
            (history[n - 1] - history[n - 4]) / 3.0
        } else {
            0.0
        };

        let mut predicted = Vec::with_capacity(self.horizon);
        let mut lower = Vec::with_capacity(self.horizon);
        let mut upper = Vec::with_capacity(self.horizon);
        for step in 1..=self.horizon {
            let y = (level + trend * step as f64).max(0.0) as f32;
            let band = (1.96 * std * (step as f64).sqrt()) as f32;
            predicted.push(y);
            lower.push((y - band).max(0.0));
            upper.push(y + band);
        }

        ForecastResult {
            metric: metric.to_string(),
            predicted,
            lower,
            upper,
            source: "baseline".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forecasts_rising_series() {
        let f = BaselineForecaster::new(4);
        let hist: Vec<f64> = (1..20).map(|x| x as f64).collect();
        let r = f.forecast("exec_count", &hist);
        assert_eq!(r.predicted.len(), 4);
        assert!(r.predicted[0] > 10.0);
    }
}
