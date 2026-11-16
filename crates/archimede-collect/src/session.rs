use anyhow::Result;
use archimede_core::{config::expand_tilde, Config, Event, EventBus, EventKind, SessionHint};
use async_trait::async_trait;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use walkdir::WalkDir;

use crate::Collector;

pub struct SessionWatcher {
    cfg: Arc<Config>,
    bus: EventBus,
    seen: tokio::sync::Mutex<HashSet<String>>,
}

impl SessionWatcher {
    pub fn new(cfg: Arc<Config>, bus: EventBus) -> Self {
        Self {
            cfg,
            bus,
            seen: tokio::sync::Mutex::new(HashSet::new()),
        }
    }

    fn infer_agent(path: &Path) -> String {
        let s = path.to_string_lossy().to_ascii_lowercase();
        if s.contains("cursor") {
            "cursor".into()
        } else if s.contains("claude") {
            "claude-code".into()
        } else if s.contains("copilot") {
            "copilot".into()
        } else if s.contains("openclaw") {
            "openclaw".into()
        } else if s.contains("hermes") {
            "hermes".into()
        } else {
            "unknown".into()
        }
    }

    fn summarize_line(line: &str) -> Option<(String, String)> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        // Try JSONL agent session formats.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let kind = v
                .get("type")
                .or_else(|| v.get("role"))
                .or_else(|| v.get("kind"))
                .and_then(|x| x.as_str())
                .unwrap_or("message")
                .to_string();
            let summary = v
                .get("content")
                .or_else(|| v.get("text"))
                .or_else(|| v.get("message"))
                .or_else(|| v.get("tool"))
                .map(|c| match c {
                    serde_json::Value::String(s) => s.chars().take(160).collect::<String>(),
                    other => {
                        let s = other.to_string();
                        s.chars().take(160).collect()
                    }
                })
                .unwrap_or_else(|| trimmed.chars().take(160).collect());
            return Some((kind, summary));
        }
        Some(("log".into(), trimmed.chars().take(160).collect()))
    }

    fn scan_file(&self, path: &Path, agent: &str) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        for (idx, line) in reader.lines().enumerate().take(200) {
            let line = line?;
            let key = format!("{}:{}", path.display(), idx);
            // Dedup handled by caller via seen set of file mtimes; here we emit last few lines.
            if let Some((kind, summary)) = Self::summarize_line(&line) {
                let hint = SessionHint {
                    agent: agent.to_string(),
                    path: path.display().to_string(),
                    kind,
                    summary,
                };
                let _ = key;
                events.push(Event::new("session_watcher", EventKind::Session(hint)));
            }
        }
        // Keep only the last few events per file to avoid flooding.
        if events.len() > 5 {
            let skip = events.len() - 5;
            events = events.into_iter().skip(skip).collect();
        }
        Ok(events)
    }
}

#[async_trait]
impl Collector for SessionWatcher {
    fn name(&self) -> &'static str {
        "session_watcher"
    }

    async fn run(&self) -> Result<()> {
        let roots: Vec<PathBuf> = self
            .cfg
            .session_logs
            .paths
            .iter()
            .map(|p| expand_tilde(p))
            .collect();
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms.max(5000));

        loop {
            for root in &roots {
                if !root.exists() {
                    continue;
                }
                for entry in WalkDir::new(root)
                    .follow_links(false)
                    .max_depth(6)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let path = entry.path();
                    let ext = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if !(ext == "jsonl" || ext == "json" || ext == "log") {
                        continue;
                    }
                    let meta = match fs::metadata(path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let modified = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let key = format!("{}@{}", path.display(), modified);
                    {
                        let mut seen = self.seen.lock().await;
                        if seen.contains(&key) {
                            continue;
                        }
                        seen.insert(key);
                        // Bound memory
                        if seen.len() > 10_000 {
                            seen.clear();
                        }
                    }
                    let agent = Self::infer_agent(path);
                    match self.scan_file(path, &agent) {
                        Ok(events) => {
                            for ev in events {
                                let _ = self.bus.publish(ev);
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, path = %path.display(), "session scan"),
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }
}
