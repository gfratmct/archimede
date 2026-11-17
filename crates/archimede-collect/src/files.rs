//! File activity collector: create / edit / delete logs under agent CWDs.
//!
//! Also derives FileOp events from harness tool spans (Write / StrReplace / Delete).

use anyhow::{bail, Result};
use archimede_core::{
    expand_tilde, AgentCatalog, Config, Event, EventBus, EventKind, FileOp, SpanKind, SpanRecord,
};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
use walkdir::WalkDir;

use crate::Collector;

#[derive(Clone, Copy)]
struct FileMeta {
    mtime_secs: i64,
    size: u64,
}

pub struct FileWatcher {
    cfg: Arc<Config>,
    catalog: Arc<AgentCatalog>,
    bus: EventBus,
}

impl FileWatcher {
    pub fn new(cfg: Arc<Config>, catalog: Arc<AgentCatalog>, bus: EventBus) -> Self {
        Self { cfg, catalog, bus }
    }

    fn ignore_dir(&self, name: &str) -> bool {
        self.cfg
            .file_watch
            .ignore_dirs
            .iter()
            .any(|d| d.eq_ignore_ascii_case(name))
    }

    fn scan_root(
        &self,
        root: &Path,
        known: &mut HashMap<String, FileMeta>,
        primed: bool,
        budget: &mut usize,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if *budget == 0 || !root.is_dir() {
            return out;
        }
        let max_depth = self.cfg.file_watch.max_depth;
        let mut seen_now: HashSet<String> = HashSet::new();

        let walker = WalkDir::new(root)
            .follow_links(false)
            .max_depth(max_depth)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    !self.ignore_dir(&name)
                } else {
                    true
                }
            });

        for entry in walker.flatten() {
            if *budget == 0 {
                break;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let path_s = path.to_string_lossy().to_string();
            seen_now.insert(path_s.clone());
            let meta = match fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime_secs = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let size = meta.len();
            let next = FileMeta { mtime_secs, size };

            match known.get(&path_s) {
                None => {
                    known.insert(path_s.clone(), next);
                    if primed {
                        out.push(("create".into(), path_s));
                        *budget = budget.saturating_sub(1);
                    }
                }
                Some(prev) if prev.mtime_secs != next.mtime_secs || prev.size != next.size => {
                    known.insert(path_s.clone(), next);
                    if primed {
                        out.push(("edit".into(), path_s));
                        *budget = budget.saturating_sub(1);
                    }
                }
                _ => {}
            }
        }

        // Deletes: paths that were under this root and disappeared.
        let root_s = root.to_string_lossy();
        let missing: Vec<String> = known
            .keys()
            .filter(|p| p.starts_with(root_s.as_ref()) && !seen_now.contains(*p))
            .cloned()
            .collect();
        for path in missing {
            known.remove(&path);
            if primed && *budget > 0 {
                out.push(("delete".into(), path));
                *budget = budget.saturating_sub(1);
            }
        }

        out
    }
}

#[async_trait]
impl Collector for FileWatcher {
    fn name(&self) -> &'static str {
        "file_watch"
    }

    async fn run(&self) -> Result<()> {
        if !self.cfg.file_watch.enabled {
            bail!("file watcher disabled in config");
        }
        tracing::info!("file watcher started (create/edit/delete logs)");
        let mut sys = System::new();
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms.max(1000));
        // path -> meta across all roots
        let mut known: HashMap<String, FileMeta> = HashMap::new();
        let mut primed = false;
        // Remember last agent attribution per root path.
        let mut root_agent: HashMap<PathBuf, (i32, Option<String>)> = HashMap::new();

        loop {
            sys.refresh_processes(ProcessesToUpdate::All, true);
            root_agent.clear();

            for (pid, proc_) in sys.processes() {
                let pid_i = pid.as_u32() as i32;
                let name = proc_.name().to_string_lossy().to_string();
                let cmdline = proc_
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                let Some(agent) = self.catalog.match_process(&name, &cmdline) else {
                    continue;
                };
                let Some(cwd) = proc_.cwd() else {
                    continue;
                };
                if !cwd.is_dir() {
                    continue;
                }
                root_agent
                    .entry(cwd.to_path_buf())
                    .and_modify(|(p, _)| {
                        if pid_i < *p {
                            *p = pid_i;
                        }
                    })
                    .or_insert((pid_i, Some(agent.name.clone())));
            }

            for root in &self.cfg.file_watch.roots {
                let path = expand_tilde(root);
                if path.is_dir() {
                    root_agent.entry(path).or_insert((0, None));
                }
            }

            let mut budget = self.cfg.file_watch.max_events_per_scan;
            for (root, (pid, agent)) in &root_agent {
                let changes = self.scan_root(root, &mut known, primed, &mut budget);
                for (op, path) in changes {
                    let _ = self.bus.publish(Event::new(
                        "file_watch",
                        EventKind::File(FileOp {
                            pid: *pid,
                            path,
                            op,
                            agent: agent.clone(),
                        }),
                    ));
                }
            }

            if !primed {
                primed = true;
                tracing::info!(
                    roots = root_agent.len(),
                    tracked = known.len(),
                    "file watcher primed (baseline established)"
                );
            }

            // Bound memory if agent leaves a huge tree.
            if known.len() > 200_000 {
                known.clear();
                primed = false;
            }

            tokio::time::sleep(interval).await;
        }
    }
}

/// Infer create/edit/delete FileOps from a harness tool span.
pub fn file_ops_from_span(span: &SpanRecord) -> Vec<FileOp> {
    if !matches!(span.kind, SpanKind::Tool) {
        return Vec::new();
    }
    let tool = span
        .attrs
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or(span.name.as_str());
    let Some(op) = tool_file_op(tool) else {
        return Vec::new();
    };
    let pid = span
        .attrs
        .get("pid")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(0);
    let mut paths = extract_paths_from_span(span);
    if paths.is_empty() {
        // Still log the tool op with a synthetic path so it appears in Logs.
        paths.push(format!("(tool:{tool})"));
    }
    paths
        .into_iter()
        .take(8)
        .map(|path| FileOp {
            pid,
            path,
            op: op.to_string(),
            agent: span.agent.clone(),
        })
        .collect()
}

fn tool_file_op(tool: &str) -> Option<&'static str> {
    let t = tool.to_ascii_lowercase();
    let t = t.replace(['-', '_'], "");
    match t.as_str() {
        "write" | "writefile" | "createfile" | "newfile" | "addfile" | "touch" => Some("create"),
        "delete" | "deletefile" | "removefile" | "rm" | "unlink" => Some("delete"),
        "strreplace" | "searchreplace" | "edit" | "editnotebook" | "applypatch"
        | "applydiff" | "patch" | "updatefile" | "modifyfile" | "replaceinfile" => Some("edit"),
        _ => None,
    }
}

fn extract_paths_from_span(span: &SpanRecord) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["path", "file", "filepath", "target", "filename"] {
        if let Some(p) = span.attrs.get(key).and_then(|v| v.as_str()) {
            push_path(&mut out, p);
        }
    }
    if let Some(arr) = span
        .attrs
        .get("paths")
        .or_else(|| span.attrs.get("files"))
        .and_then(|v| v.as_array())
    {
        for v in arr.iter().filter_map(|v| v.as_str()).take(8) {
            push_path(&mut out, v);
        }
    }
    // Fall back to scanning summaries for absolute / relative path-ish tokens.
    for blob in [span.input_summary.as_deref(), span.output_summary.as_deref()]
        .into_iter()
        .flatten()
    {
        for token in blob.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`')
        {
            if looks_like_path(token) {
                push_path(&mut out, token);
            }
        }
    }
    out
}

fn push_path(out: &mut Vec<String>, p: &str) {
    let p = p.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if p.is_empty() || out.iter().any(|x| x == p) {
        return;
    }
    out.push(p.to_string());
}

fn looks_like_path(token: &str) -> bool {
    if token.len() < 3 || token.len() > 400 {
        return false;
    }
    if token.starts_with('/') || token.starts_with("~/") || token.starts_with("./") {
        return true;
    }
    // Heuristic: has a slash and a file extension, or looks like src/foo.rs
    token.contains('/')
        && (token.contains('.') || token.ends_with(".rs") || token.ends_with(".ts"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use archimede_core::SpanKind;
    use chrono::Utc;
    use serde_json::json;

    fn tool_span(name: &str, attrs: serde_json::Value) -> SpanRecord {
        SpanRecord {
            trace_id: "t1".into(),
            span_id: "s1".into(),
            parent_span_id: None,
            name: name.into(),
            kind: SpanKind::Tool,
            agent: Some("cursor".into()),
            harness: None,
            model: None,
            input_summary: None,
            output_summary: None,
            attrs,
            start_ts: Utc::now(),
            end_ts: None,
            status: Some("ok".into()),
            token_usage: None,
        }
    }

    #[test]
    fn span_write_becomes_create() {
        let span = tool_span("Write", json!({"tool": "Write", "path": "/tmp/x.rs"}));
        let ops = file_ops_from_span(&span);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, "create");
        assert_eq!(ops[0].path, "/tmp/x.rs");
    }

    #[test]
    fn span_delete_and_edit() {
        let del = tool_span("Delete", json!({"path": "/tmp/gone.txt"}));
        assert_eq!(file_ops_from_span(&del)[0].op, "delete");

        let edit = tool_span("StrReplace", json!({"path": "/tmp/a.rs"}));
        assert_eq!(file_ops_from_span(&edit)[0].op, "edit");
    }
}
