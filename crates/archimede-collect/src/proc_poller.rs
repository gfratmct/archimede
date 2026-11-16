use anyhow::Result;
use archimede_core::{AgentCatalog, Config, Event, EventBus, EventKind, ProcessSnapshot};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};

use crate::Collector;

pub struct ProcPoller {
    cfg: Arc<Config>,
    catalog: Arc<AgentCatalog>,
    bus: EventBus,
}

impl ProcPoller {
    pub fn new(cfg: Arc<Config>, catalog: Arc<AgentCatalog>, bus: EventBus) -> Self {
        Self { cfg, catalog, bus }
    }
}

#[derive(Default)]
struct AgentAgg {
    pid: i32,
    ppid: i32,
    comm: String,
    cmdline: String,
    cwd: Option<String>,
    rss_bytes: u64,
    cpu_pct: f32,
    family: String,
    count: u64,
    max_rss: u64,
}

#[async_trait]
impl Collector for ProcPoller {
    fn name(&self) -> &'static str {
        "proc_poller"
    }

    async fn run(&self) -> Result<()> {
        let mut sys = System::new();
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms);

        loop {
            sys.refresh_processes(ProcessesToUpdate::All, true);
            // One summary snapshot per agent per tick (avoids SQLite flood).
            let mut by_agent: HashMap<String, AgentAgg> = HashMap::new();

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
                let cpu = proc_.cpu_usage();
                let rss = proc_.memory();
                let cwd = proc_.cwd().map(|p| p.to_string_lossy().to_string());
                let ppid = proc_.parent().map(|p| p.as_u32() as i32).unwrap_or(0);

                let entry = by_agent.entry(agent.name.clone()).or_insert_with(|| AgentAgg {
                    family: agent.family.clone(),
                    ..Default::default()
                });
                entry.count += 1;
                entry.rss_bytes = entry.rss_bytes.saturating_add(rss);
                entry.cpu_pct += cpu;
                if rss >= entry.max_rss {
                    entry.max_rss = rss;
                    entry.pid = pid_i;
                    entry.ppid = ppid;
                    entry.comm = name;
                    entry.cmdline = cmdline.chars().take(160).collect();
                    entry.cwd = cwd;
                }
            }

            for (agent_name, agg) in by_agent {
                let snap = ProcessSnapshot {
                    pid: agg.pid,
                    ppid: agg.ppid,
                    comm: agg.comm,
                    cmdline: format!("procs={} | {}", agg.count, agg.cmdline),
                    cwd: agg.cwd,
                    rss_bytes: agg.rss_bytes,
                    cpu_pct: agg.cpu_pct,
                    agent: Some(agent_name),
                    family: Some(agg.family),
                };
                let _ = self
                    .bus
                    .publish(Event::new("proc_poller", EventKind::ProcessSnapshot(snap)));
            }
            tokio::time::sleep(interval).await;
        }
    }
}
