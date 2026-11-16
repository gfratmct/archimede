//! System-One classifier: HTTP client for open Jev-compatible servers + rules.

mod client;
mod rules;

pub use client::{Classification, SystemOneClient, SystemOneRequest, SystemOneResponse};
pub use rules::rule_classify;

use anyhow::Result;
use archimede_core::{BehaviorLabel, Config};
use archimede_features::FeatureBucket;

pub struct BehaviorClassifier {
    client: SystemOneClient,
    fallback: bool,
}

impl BehaviorClassifier {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            client: SystemOneClient::new(
                &cfg.classify.endpoint,
                &cfg.classify.model,
                cfg.classify.timeout_ms,
            ),
            fallback: cfg.classify.fallback_rules,
        }
    }

    pub async fn classify_bucket(&self, bucket: &FeatureBucket) -> Result<Classification> {
        let state = bucket.to_state_text();
        match self.client.classify_behavior(&state).await {
            Ok(c) => Ok(c),
            Err(e) => {
                if self.fallback {
                    tracing::debug!(error = %e, "system-one unavailable; using rules");
                    Ok(rule_classify(bucket))
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn classify_rules(&self, bucket: &FeatureBucket) -> Classification {
        rule_classify(bucket)
    }
}

pub fn label_from_str(s: &str) -> BehaviorLabel {
    BehaviorLabel::parse(s).unwrap_or(BehaviorLabel::Idle)
}
