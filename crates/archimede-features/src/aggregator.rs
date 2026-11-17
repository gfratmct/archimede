use archimede_core::{Config, Event, EventKind, RiskFlag, SpanKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Per-agent metrics for a fixed time bucket.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureBucket {
    pub ts: DateTime<Utc>,
    pub agent: String,
    pub process_samples: u64,
    pub exec_count: u64,
    pub unique_binaries: HashSet<String>,
    pub files_written: u64,
    pub files_deleted: u64,
    pub socket_count: u64,
    pub distinct_remotes: HashSet<String>,
    pub session_events: u64,
    pub rss_bytes_max: u64,
    pub cpu_pct_max: f32,
    pub egress_proxy_score: f64,
    pub llm_wait_hints: u64,
    pub shell_hints: u64,
    pub coding_hints: u64,
    pub resource_spikes: u64,
    pub new_remotes: u64,
    pub span_count: u64,
    pub tool_calls: u64,
    pub llm_calls: u64,
    pub rss_delta_max: i64,
    pub cpu_delta_max: f32,
    pub fd_count_max: u64,
}

impl FeatureBucket {
    pub fn new(ts: DateTime<Utc>, agent: impl Into<String>) -> Self {
        Self {
            ts,
            agent: agent.into(),
            ..Default::default()
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ts": self.ts.to_rfc3339(),
            "agent": self.agent,
            "process_samples": self.process_samples,
            "exec_count": self.exec_count,
            "unique_binaries": self.unique_binaries.len(),
            "files_written": self.files_written,
            "files_deleted": self.files_deleted,
            "socket_count": self.socket_count,
            "distinct_remotes": self.distinct_remotes.len(),
            "session_events": self.session_events,
            "rss_bytes_max": self.rss_bytes_max,
            "cpu_pct_max": self.cpu_pct_max,
            "egress_proxy_score": self.egress_proxy_score,
            "llm_wait_hints": self.llm_wait_hints,
            "shell_hints": self.shell_hints,
            "coding_hints": self.coding_hints,
            "resource_spikes": self.resource_spikes,
            "new_remotes": self.new_remotes,
            "span_count": self.span_count,
            "tool_calls": self.tool_calls,
            "llm_calls": self.llm_calls,
            "rss_delta_max": self.rss_delta_max,
            "cpu_delta_max": self.cpu_delta_max,
            "fd_count_max": self.fd_count_max,
        })
    }

    /// Compact textual state for System-One classification.
    pub fn to_state_text(&self) -> String {
        format!(
            "agent={}; execs={}; binaries={}; writes={}; deletes={}; sockets={}; remotes={}; sessions={}; cpu_max={:.1}; rss_max={}; egress_score={:.2}; llm_wait={}; shell={}; coding={}; spikes={}; new_remotes={}; spans={}; tools={}; llms={}",
            self.agent,
            self.exec_count,
            self.unique_binaries.len(),
            self.files_written,
            self.files_deleted,
            self.socket_count,
            self.distinct_remotes.len(),
            self.session_events,
            self.cpu_pct_max,
            self.rss_bytes_max,
            self.egress_proxy_score,
            self.llm_wait_hints,
            self.shell_hints,
            self.coding_hints,
            self.resource_spikes,
            self.new_remotes,
            self.span_count,
            self.tool_calls,
            self.llm_calls,
        )
    }

    pub fn metric_map(&self) -> HashMap<String, f64> {
        let mut m = HashMap::new();
        m.insert("exec_count".into(), self.exec_count as f64);
        m.insert("unique_binaries".into(), self.unique_binaries.len() as f64);
        m.insert("files_written".into(), self.files_written as f64);
        m.insert("files_deleted".into(), self.files_deleted as f64);
        m.insert("socket_count".into(), self.socket_count as f64);
        m.insert(
            "distinct_remotes".into(),
            self.distinct_remotes.len() as f64,
        );
        m.insert("session_events".into(), self.session_events as f64);
        m.insert("rss_bytes_max".into(), self.rss_bytes_max as f64);
        m.insert("cpu_pct_max".into(), self.cpu_pct_max as f64);
        m.insert("egress_proxy_score".into(), self.egress_proxy_score);
        m.insert("resource_spikes".into(), self.resource_spikes as f64);
        m.insert("new_remotes".into(), self.new_remotes as f64);
        m.insert("span_count".into(), self.span_count as f64);
        m.insert("tool_calls".into(), self.tool_calls as f64);
        m.insert("llm_calls".into(), self.llm_calls as f64);
        m
    }

    pub fn evaluate_risks(&self, cfg: &Config) -> Vec<(RiskFlag, String, f32)> {
        let mut out = Vec::new();
        if self.exec_count >= cfg.alerts.exec_rate_per_bucket {
            out.push((
                RiskFlag::HighExecRate,
                format!(
                    "{} executed {} processes in one bucket",
                    self.agent, self.exec_count
                ),
                (self.exec_count as f32 / cfg.alerts.exec_rate_per_bucket as f32).min(1.0),
            ));
        }
        if self.files_deleted >= cfg.alerts.delete_rate_per_bucket {
            out.push((
                RiskFlag::MassDelete,
                format!(
                    "{} deleted {} files in one bucket",
                    self.agent, self.files_deleted
                ),
                (self.files_deleted as f32 / cfg.alerts.delete_rate_per_bucket as f32).min(1.0),
            ));
        }
        let egress_proxy_bytes = (self.egress_proxy_score * 1_000_000.0) as u64;
        if egress_proxy_bytes >= cfg.alerts.egress_bytes_per_bucket {
            out.push((
                RiskFlag::HighEgress,
                format!(
                    "{} high egress proxy score {:.2}",
                    self.agent, self.egress_proxy_score
                ),
                (egress_proxy_bytes as f32 / cfg.alerts.egress_bytes_per_bucket as f32).min(1.0),
            ));
        }
        if self.unique_binaries.len() as u64 >= 25 {
            out.push((
                RiskFlag::UnknownBinaryStorm,
                format!(
                    "{} touched {} unique binaries",
                    self.agent,
                    self.unique_binaries.len()
                ),
                0.6,
            ));
        }
        out
    }
}

pub struct BucketAggregator {
    bucket_secs: i64,
    current_start: DateTime<Utc>,
    buckets: HashMap<String, FeatureBucket>,
}

impl BucketAggregator {
    pub fn new(bucket_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            bucket_secs: bucket_secs as i64,
            current_start: floor_bucket(now, bucket_secs as i64),
            buckets: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, event: &Event) -> Vec<FeatureBucket> {
        let mut flushed = Vec::new();
        let ts = event.ts;
        let start = floor_bucket(ts, self.bucket_secs);
        if start > self.current_start {
            flushed.extend(self.flush());
            self.current_start = start;
        }

        let agent = event
            .agent
            .clone()
            .or_else(|| match &event.kind {
                EventKind::Exec { comm, .. } => Some(comm.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "system".into());

        let b = self
            .buckets
            .entry(agent.clone())
            .or_insert_with(|| FeatureBucket::new(self.current_start, agent));

        match &event.kind {
            EventKind::ProcessSnapshot(p) => {
                b.process_samples += 1;
                b.rss_bytes_max = b.rss_bytes_max.max(p.rss_bytes);
                b.cpu_pct_max = b.cpu_pct_max.max(p.cpu_pct);
                b.unique_binaries.insert(p.comm.clone());
            }
            EventKind::Exec {
                comm,
                argv_summary,
                ..
            } => {
                b.exec_count += 1;
                b.unique_binaries.insert(comm.clone());
                let lower = argv_summary.to_ascii_lowercase();
                if lower.contains("bash")
                    || lower.contains("zsh")
                    || lower.contains("sh ")
                    || lower.contains("/bin/")
                {
                    b.shell_hints += 1;
                }
            }
            EventKind::File(f) => match f.op.as_str() {
                "unlink" | "delete" => b.files_deleted += 1,
                "write" | "open" | "create" => b.files_written += 1,
                _ => {}
            },
            EventKind::NetworkMeta(n) => {
                b.socket_count += 1;
                b.distinct_remotes.insert(n.remote.clone());
                b.egress_proxy_score += 0.1;
            }
            EventKind::Connect { dest, sni, .. } => {
                b.socket_count += 1;
                let remote = sni.clone().unwrap_or_else(|| dest.clone());
                if b.distinct_remotes.insert(remote.clone()) {
                    b.new_remotes += 1;
                }
                b.egress_proxy_score += 0.5;
                let lower = remote.to_ascii_lowercase();
                if lower.contains("openai")
                    || lower.contains("anthropic")
                    || lower.contains("copilot")
                    || lower.contains("ollama")
                {
                    b.llm_wait_hints += 1;
                }
            }
            EventKind::Dns { query, .. } => {
                if b.distinct_remotes.insert(query.clone()) {
                    b.new_remotes += 1;
                }
                let lower = query.to_ascii_lowercase();
                if lower.contains("openai")
                    || lower.contains("anthropic")
                    || lower.contains("api.")
                {
                    b.llm_wait_hints += 1;
                }
            }
            EventKind::Session(s) => {
                b.session_events += 1;
                let lower = format!("{} {}", s.kind, s.summary).to_ascii_lowercase();
                if lower.contains("tool") || lower.contains("shell") || lower.contains("bash") {
                    b.shell_hints += 1;
                }
                if lower.contains("edit")
                    || lower.contains("write")
                    || lower.contains("code")
                    || lower.contains("patch")
                {
                    b.coding_hints += 1;
                }
                if lower.contains("assistant") || lower.contains("thinking") {
                    b.llm_wait_hints += 1;
                }
            }
            EventKind::ResourceDelta(d) => {
                b.resource_spikes += 1;
                b.rss_delta_max = b.rss_delta_max.max(d.rss_delta.abs());
                b.cpu_delta_max = b.cpu_delta_max.max(d.cpu_delta.abs());
                if let Some(fd) = d.fd_count {
                    b.fd_count_max = b.fd_count_max.max(fd);
                }
            }
            EventKind::Span(span) => {
                b.span_count += 1;
                match span.kind {
                    SpanKind::Tool => b.tool_calls += 1,
                    SpanKind::Llm => {
                        b.llm_calls += 1;
                        b.llm_wait_hints += 1;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        flushed
    }

    pub fn flush(&mut self) -> Vec<FeatureBucket> {
        let out: Vec<_> = self.buckets.drain().map(|(_, v)| v).collect();
        out
    }

    pub fn pending(&self) -> impl Iterator<Item = &FeatureBucket> {
        self.buckets.values()
    }
}

fn floor_bucket(ts: DateTime<Utc>, secs: i64) -> DateTime<Utc> {
    let epoch = ts.timestamp();
    let floored = epoch - epoch.rem_euclid(secs);
    DateTime::from_timestamp(floored, 0).unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archimede_core::{Event, EventKind, ProcessSnapshot};

    #[test]
    fn aggregates_process() {
        let mut agg = BucketAggregator::new(30);
        let ev = Event::new(
            "test",
            EventKind::ProcessSnapshot(ProcessSnapshot {
                pid: 1,
                ppid: 0,
                comm: "cursor".into(),
                cmdline: "cursor".into(),
                cwd: None,
                rss_bytes: 100,
                cpu_pct: 2.0,
                agent: Some("cursor".into()),
                family: Some("coding_agent".into()),
            }),
        );
        agg.ingest(&ev);
        let pending: Vec<_> = agg.pending().collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].process_samples, 1);
    }
}
