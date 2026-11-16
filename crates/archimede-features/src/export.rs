use crate::aggregator::FeatureBucket;
use anyhow::Result;
use serde_json::json;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Write buckets as JSONL for Python fine-tune / validation pipelines.
pub fn export_buckets_jsonl(path: impl AsRef<Path>, buckets: &[FeatureBucket]) -> Result<()> {
    let file = File::create(path)?;
    let mut w = BufWriter::new(file);
    for b in buckets {
        writeln!(w, "{}", b.to_json())?;
    }
    Ok(())
}

/// Build a multivariate series matrix suitable for Timestral-style inputs.
/// Returns (timestamps, metric_names, values[metric][time]).
pub fn timeseries_from_buckets(
    buckets: &[FeatureBucket],
    metrics: &[&str],
) -> (Vec<String>, Vec<String>, Vec<Vec<f64>>) {
    let mut sorted = buckets.to_vec();
    sorted.sort_by_key(|b| b.ts);

    let names: Vec<String> = metrics.iter().map(|m| (*m).to_string()).collect();
    let ts: Vec<String> = sorted.iter().map(|b| b.ts.to_rfc3339()).collect();
    let mut values = Vec::with_capacity(metrics.len());
    for metric in metrics {
        let series: Vec<f64> = sorted
            .iter()
            .map(|b| *b.metric_map().get(*metric).unwrap_or(&0.0))
            .collect();
        values.push(series);
    }
    (ts, names, values)
}

pub fn forecast_payload(
    agent: &str,
    buckets: &[FeatureBucket],
    metrics: &[&str],
    horizon: usize,
) -> serde_json::Value {
    let (ts, names, values) = timeseries_from_buckets(buckets, metrics);
    json!({
        "agent": agent,
        "timestamps": ts,
        "metrics": names,
        "values": values,
        "horizon": horizon,
    })
}
