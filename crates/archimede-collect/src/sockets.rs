use anyhow::Result;
use archimede_core::{AgentCatalog, Config, Event, EventBus, EventKind, NetworkMeta};
use async_trait::async_trait;
use procfs::process::FDTarget;
use procfs::process::Process;
use std::sync::Arc;
use std::time::Duration;

use crate::Collector;

pub struct SocketPoller {
    cfg: Arc<Config>,
    catalog: Arc<AgentCatalog>,
    bus: EventBus,
}

impl SocketPoller {
    pub fn new(cfg: Arc<Config>, catalog: Arc<AgentCatalog>, bus: EventBus) -> Self {
        Self { cfg, catalog, bus }
    }
}

#[async_trait]
impl Collector for SocketPoller {
    fn name(&self) -> &'static str {
        "socket_poller"
    }

    async fn run(&self) -> Result<()> {
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms.max(3000));
        loop {
            if let Err(e) = self.scan_once() {
                tracing::debug!(error = %e, "socket scan");
            }
            tokio::time::sleep(interval).await;
        }
    }
}

impl SocketPoller {
    fn scan_once(&self) -> Result<()> {
        let tcp = procfs::net::tcp()?;
        let tcp6 = procfs::net::tcp6().unwrap_or_default();

        // inode -> (local, remote, state)
        let mut by_inode = std::collections::HashMap::new();
        for entry in tcp.into_iter().chain(tcp6.into_iter()) {
            by_inode.insert(
                entry.inode,
                (
                    format!("{}", entry.local_address),
                    format!("{}", entry.remote_address),
                    format!("{:?}", entry.state),
                ),
            );
        }

        for process in procfs::process::all_processes()?.flatten() {
            let Ok(stat) = process.stat() else {
                continue;
            };
            let cmdline = process
                .cmdline()
                .unwrap_or_default()
                .join(" ");
            let matched = self.catalog.match_process(&stat.comm, &cmdline);
            let Some(agent) = matched else {
                continue;
            };

            if let Ok(fds) = process.fd() {
                for fd in fds.flatten() {
                    if let FDTarget::Socket(inode) = fd.target {
                        if let Some((local, remote, state)) = by_inode.get(&inode) {
                            let meta = NetworkMeta {
                                pid: process.pid,
                                local: local.clone(),
                                remote: remote.clone(),
                                state: state.clone(),
                                agent: Some(agent.name.clone()),
                            };
                            let _ = self
                                .bus
                                .publish(Event::new("socket_poller", EventKind::NetworkMeta(meta)));
                        }
                    }
                }
            }

            // Also emit connect-style summary for established remotes.
            let _ = Process::new(process.pid);
            let _ = agent;
        }
        Ok(())
    }
}
