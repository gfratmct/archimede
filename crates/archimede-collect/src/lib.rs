//! Collectors for process, network metadata, optional eBPF, and session logs.

pub mod ebpf;
pub mod proc_poller;
pub mod session;
pub mod sockets;

pub use ebpf::EbpfCollector;
pub use proc_poller::ProcPoller;
pub use session::SessionWatcher;
pub use sockets::SocketPoller;

use anyhow::Result;
use archimede_core::{AgentCatalog, Config, EventBus};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task::JoinHandle;

#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self) -> Result<()>;
}

/// Spawn all configured collectors; returns join handles.
pub fn spawn_all(
    cfg: Arc<Config>,
    catalog: Arc<AgentCatalog>,
    bus: EventBus,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    let poller = ProcPoller::new(cfg.clone(), catalog.clone(), bus.clone());
    handles.push(tokio::spawn(async move {
        if let Err(e) = poller.run().await {
            tracing::error!(error = %e, "proc poller stopped");
        }
    }));

    let sockets = SocketPoller::new(cfg.clone(), catalog.clone(), bus.clone());
    handles.push(tokio::spawn(async move {
        if let Err(e) = sockets.run().await {
            tracing::error!(error = %e, "socket poller stopped");
        }
    }));

    let sessions = SessionWatcher::new(cfg.clone(), bus.clone());
    handles.push(tokio::spawn(async move {
        if let Err(e) = sessions.run().await {
            tracing::error!(error = %e, "session watcher stopped");
        }
    }));

    if cfg.daemon.enable_ebpf {
        let ebpf = EbpfCollector::new(cfg.clone(), catalog, bus);
        handles.push(tokio::spawn(async move {
            if let Err(e) = ebpf.run().await {
                tracing::warn!(error = %e, "eBPF collector unavailable; continuing without it");
            }
        }));
    }

    handles
}
