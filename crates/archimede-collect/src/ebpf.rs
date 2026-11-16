//! Optional eBPF collector.
//!
//! When the `ebpf` feature is enabled and CAP_BPF is available, this module
//! will attach exec/connect/openat probes via Aya. Until then it runs a
//! userspace fallback that synthesizes exec-like events from /proc delta scans
//! so the rest of the pipeline stays testable without privileged access.

use anyhow::{bail, Result};
use archimede_core::{AgentCatalog, Config, Event, EventBus, EventKind};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::Collector;

pub struct EbpfCollector {
    cfg: Arc<Config>,
    catalog: Arc<AgentCatalog>,
    bus: EventBus,
}

impl EbpfCollector {
    pub fn new(cfg: Arc<Config>, catalog: Arc<AgentCatalog>, bus: EventBus) -> Self {
        Self { cfg, catalog, bus }
    }

    #[cfg(feature = "ebpf")]
    async fn run_aya(&self) -> Result<()> {
        // Placeholder for Aya-based probes. Keep feature-gated so default builds
        // do not require kernel headers or privileged CI.
        bail!("aya eBPF probes are not compiled into this build; rebuild with --features ebpf once probes are provided")
    }

    async fn run_userspace_fallback(&self) -> Result<()> {
        tracing::info!("eBPF unavailable or disabled feature; using /proc exec-delta fallback");
        let mut seen: HashSet<(i32, String)> = HashSet::new();
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms);
        loop {
            if let Ok(procs) = procfs::process::all_processes() {
                for process in procs.flatten() {
                    let Ok(stat) = process.stat() else {
                        continue;
                    };
                    let cmdline = process.cmdline().unwrap_or_default().join(" ");
                    let key = (process.pid, cmdline.clone());
                    if !seen.insert(key) {
                        continue;
                    }
                    if seen.len() > 50_000 {
                        seen.clear();
                    }
                    let matched = self.catalog.match_process(&stat.comm, &cmdline);
                    let agent_name = matched.as_ref().map(|m| m.name.clone());
                    // Attribute child shells under known agents via ppid later; for now emit matched only.
                    if agent_name.is_none() {
                        continue;
                    }
                    let _ = self.bus.publish(Event::new(
                        "ebpf_fallback",
                        EventKind::Exec {
                            pid: process.pid,
                            ppid: stat.ppid,
                            comm: stat.comm.clone(),
                            argv_summary: cmdline.chars().take(200).collect(),
                        },
                    ));
                }
            }
            tokio::time::sleep(interval).await;
        }
    }
}

#[async_trait]
impl Collector for EbpfCollector {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    async fn run(&self) -> Result<()> {
        #[cfg(feature = "ebpf")]
        {
            match self.run_aya().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(error = %e, "falling back from aya eBPF");
                }
            }
        }
        if !self.cfg.daemon.enable_ebpf {
            bail!("eBPF collector disabled in config");
        }
        self.run_userspace_fallback().await
    }
}
