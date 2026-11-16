//! Bucket aggregator: collapse raw events into per-agent feature vectors.

mod aggregator;
mod export;

pub use aggregator::{BucketAggregator, FeatureBucket};
pub use export::{export_buckets_jsonl, forecast_payload, timeseries_from_buckets};
