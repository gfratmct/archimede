use anyhow::Result;
use archimede_core::{AgentCatalog, Config, EventBus};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Collector;

pub struct SocketPoller {
    cfg: Arc<Config>,
    catalog: Arc<AgentCatalog>,
    bus: EventBus,
    seen_remotes: Mutex<HashSet<String>>,
}

impl SocketPoller {
    pub fn new(cfg: Arc<Config>, catalog: Arc<AgentCatalog>, bus: EventBus) -> Self {
        Self {
            cfg,
            catalog,
            bus,
            seen_remotes: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl Collector for SocketPoller {
    fn name(&self) -> &'static str {
        "socket_poller"
    }

    async fn run(&self) -> Result<()> {
        let interval = Duration::from_millis(self.cfg.daemon.poll_interval_ms.max(3000));

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&self.catalog, &self.bus, &self.seen_remotes);
            tracing::warn!(
                "socket metadata collection requires Linux /proc; socket_poller is idle on this platform"
            );
            loop {
                tokio::time::sleep(interval).await;
            }
        }

        #[cfg(target_os = "linux")]
        {
            loop {
                if let Err(e) = self.scan_once() {
                    tracing::debug!(error = %e, "socket scan");
                }
                tokio::time::sleep(interval).await;
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl SocketPoller {
    fn scan_once(&self) -> Result<()> {
        use archimede_core::{Event, EventKind, NetworkMeta};
        use procfs::process::FDTarget;

        let tcp = procfs::net::tcp()?;
        let tcp6 = procfs::net::tcp6().unwrap_or_default();

        // inode -> (local, remote, state, port)
        let mut by_inode = std::collections::HashMap::new();
        for entry in tcp.into_iter().chain(tcp6.into_iter()) {
            let remote = format!("{}", entry.remote_address);
            let port = entry.remote_address.port();
            by_inode.insert(
                entry.inode,
                (
                    format!("{}", entry.local_address),
                    remote,
                    format!("{:?}", entry.state),
                    port,
                ),
            );
        }

        let mut seen = self
            .seen_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        for process in procfs::process::all_processes()?.flatten() {
            let Ok(stat) = process.stat() else {
                continue;
            };
            let cmdline = process.cmdline().unwrap_or_default().join(" ");
            let matched = self.catalog.match_process(&stat.comm, &cmdline);
            let Some(agent) = matched else {
                continue;
            };

            if let Ok(fds) = process.fd() {
                for fd in fds.flatten() {
                    if let FDTarget::Socket(inode) = fd.target {
                        if let Some((local, remote, state, port)) = by_inode.get(&inode) {
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

                            let is_new = seen.insert(remote.clone());
                            if is_new && *port != 0 {
                                let dest = remote.clone();
                                let _ = self.bus.publish(Event::new(
                                    "socket_poller",
                                    EventKind::Connect {
                                        pid: process.pid,
                                        dest,
                                        port: *port,
                                        sni: None,
                                    },
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
