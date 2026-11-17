use anyhow::Result;
use archimede_core::{
    AgentCatalog, Config, Event, EventBus, EventKind, ProcessSnapshot, ResourceDelta,
};
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

#[derive(Clone, Copy, Default)]
struct PrevRes {
    rss: u64,
    cpu: f32,
}

#[async_trait]
impl Collector for ProcPoller {
    fn name(&self) -> &'static str {
        "proc_poller"
    }

    async fn run(&self) -> Result<()> {
        let mut sys = System::new();
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms);
        let spike_pct = self.cfg.policy.flag_on_resource_spike_pct.max(1) as f64;
        let mut prev: HashMap<String, PrevRes> = HashMap::new();

        loop {
            sys.refresh_processes(ProcessesToUpdate::All, true);
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
                    comm: agg.comm.clone(),
                    cmdline: format!("procs={} | {}", agg.count, agg.cmdline),
                    cwd: agg.cwd.clone(),
                    rss_bytes: agg.rss_bytes,
                    cpu_pct: agg.cpu_pct,
                    agent: Some(agent_name.clone()),
                    family: Some(agg.family.clone()),
                };
                let _ = self
                    .bus
                    .publish(Event::new("proc_poller", EventKind::ProcessSnapshot(snap)));

                if let Some(old) = prev.get(&agent_name) {
                    let rss_delta = agg.rss_bytes as i64 - old.rss as i64;
                    let cpu_delta = agg.cpu_pct - old.cpu;
                    let rss_spike = old.rss > 0
                        && (agg.rss_bytes as f64) > (old.rss as f64) * (spike_pct / 100.0);
                    let cpu_spike = old.cpu > 1.0 && agg.cpu_pct > old.cpu * (spike_pct as f32 / 100.0);
                    if rss_spike || cpu_spike {
                        let reason = if rss_spike && cpu_spike {
                            "rss_and_cpu_spike"
                        } else if rss_spike {
                            "rss_spike"
                        } else {
                            "cpu_spike"
                        };
                        let delta = ResourceDelta {
                            pid: agg.pid,
                            agent: Some(agent_name.clone()),
                            cpu_delta,
                            rss_delta,
                            fd_count: None,
                            thread_count: None,
                            change_reason: reason.into(),
                        };
                        let _ = self.bus.publish(Event::new(
                            "proc_poller",
                            EventKind::ResourceDelta(delta),
                        ));
                    }
                }
                prev.insert(
                    agent_name,
                    PrevRes {
                        rss: agg.rss_bytes,
                        cpu: agg.cpu_pct,
                    },
                );
            }
            tokio::time::sleep(interval).await;
        }
    }
}
