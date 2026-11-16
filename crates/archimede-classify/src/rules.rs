use crate::client::Classification;
use archimede_core::BehaviorLabel;
use archimede_features::FeatureBucket;
use std::collections::HashMap;

/// Deterministic local classifier used when System-One is offline.
pub fn rule_classify(bucket: &FeatureBucket) -> Classification {
    let mut scores: HashMap<BehaviorLabel, f32> = HashMap::new();
    scores.insert(BehaviorLabel::Idle, 0.1);

    if bucket.exec_count == 0
        && bucket.session_events == 0
        && bucket.socket_count == 0
        && bucket.process_samples <= 1
    {
        scores.insert(BehaviorLabel::Idle, 0.9);
    }
    if bucket.coding_hints > 0 || bucket.files_written > 0 {
        scores.insert(
            BehaviorLabel::Coding,
            0.4 + 0.1 * bucket.coding_hints.min(5) as f32,
        );
    }
    if bucket.shell_hints > 0 || bucket.exec_count > 3 {
        scores.insert(
            BehaviorLabel::ShellTools,
            0.35 + 0.08 * bucket.shell_hints.min(6) as f32,
        );
    }
    if bucket.llm_wait_hints > 0 {
        scores.insert(
            BehaviorLabel::LlmWait,
            0.4 + 0.1 * bucket.llm_wait_hints.min(5) as f32,
        );
    }
    if bucket.files_deleted > 5 || bucket.egress_proxy_score > 20.0 {
        scores.insert(BehaviorLabel::RiskyEgress, 0.75);
    }
    if bucket.session_events > 0 && bucket.exec_count == 0 && bucket.coding_hints == 0 {
        scores.insert(BehaviorLabel::Planning, 0.45);
    }
    if bucket.unique_binaries.iter().any(|b| {
        let l = b.to_ascii_lowercase();
        l.contains("pytest") || l.contains("cargo") || l.contains("jest") || l.contains("vitest")
    }) {
        scores.insert(BehaviorLabel::Testing, 0.55);
    }
    if bucket.distinct_remotes.iter().any(|r| {
        let l = r.to_ascii_lowercase();
        l.contains("http") || l.contains(":443") || l.contains("www.")
    }) && bucket.coding_hints == 0
    {
        scores.insert(BehaviorLabel::Browsing, 0.4);
    }

    let (label, confidence) = scores
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or((BehaviorLabel::Idle, 0.3));

    let mut probabilities = HashMap::new();
    probabilities.insert(label.as_str().to_string(), confidence);

    Classification {
        label,
        confidence,
        source: "rules".into(),
        probabilities,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_storm() {
        let mut b = FeatureBucket::default();
        b.agent = "cursor".into();
        b.exec_count = 12;
        b.shell_hints = 8;
        let c = rule_classify(&b);
        assert_eq!(c.label, BehaviorLabel::ShellTools);
    }
}
