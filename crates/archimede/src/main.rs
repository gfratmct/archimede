//! Archimede CLI and daemon entrypoint.

use anyhow::Result;
use archimede::core::{Config, Store};
use archimede::daemon;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "archimede", about = "Local agent awareness engine", version)]
struct Cli {
    /// Path to archimede.yaml
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the monitoring daemon (collect + classify + forecast + API)
    Daemon {
        /// Override bind address (default from config)
        #[arg(long)]
        bind: Option<String>,
    },
    /// Print recent events
    Logs {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        agent: Option<String>,
    },
    /// Print aggregate stats
    Stats,
    /// Print recent alerts
    Alerts {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Export feature buckets as JSONL for ML pipelines
    Export {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// One-shot scan of current agent processes
    Scan,
    /// Show resolved config
    Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("archimede=info".parse()?))
        .init();

    let cli = Cli::parse();
    let cfg = Config::load_or_default(cli.config.as_deref())?;

    match cli.command {
        Commands::Daemon { bind } => {
            let mut cfg = cfg;
            if let Some(b) = bind {
                cfg.daemon.bind = b;
            }
            daemon::run(Arc::new(cfg)).await
        }
        Commands::Logs { limit, agent } => {
            let store = open_store(&cfg)?;
            let events = store.recent_events(limit, agent.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&events)?);
            Ok(())
        }
        Commands::Stats => {
            let store = open_store(&cfg)?;
            let stats = store.stats()?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
            Ok(())
        }
        Commands::Alerts { limit } => {
            let store = open_store(&cfg)?;
            let alerts = store.recent_alerts(limit)?;
            println!("{}", serde_json::to_string_pretty(&alerts)?);
            Ok(())
        }
        Commands::Export { out, limit } => {
            let store = open_store(&cfg)?;
            let events = store.recent_events(limit, None)?;
            let mut agg = archimede::features::BucketAggregator::new(cfg.daemon.bucket_secs);
            let mut buckets = Vec::new();
            for ev in &events {
                buckets.extend(agg.ingest(ev));
            }
            buckets.extend(agg.flush());
            archimede::features::export_buckets_jsonl(&out, &buckets)?;
            println!("wrote {} buckets to {}", buckets.len(), out.display());
            Ok(())
        }
        Commands::Scan => {
            let catalog = archimede::core::AgentCatalog::from_config(&cfg.attribution.agents);
            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            let mut found = Vec::new();
            for (pid, proc_) in sys.processes() {
                let name = proc_.name().to_string_lossy().to_string();
                let cmdline = proc_
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                if let Some(m) = catalog.match_process(&name, &cmdline) {
                    found.push(serde_json::json!({
                        "pid": pid.as_u32(),
                        "comm": name,
                        "agent": m.name,
                        "family": m.family,
                        "rss_bytes": proc_.memory(),
                        "cpu_pct": proc_.cpu_usage(),
                    }));
                }
            }
            println!("{}", serde_json::to_string_pretty(&found)?);
            Ok(())
        }
        Commands::Config => {
            println!("{}", serde_yaml::to_string(&cfg)?);
            Ok(())
        }
    }
}

fn open_store(cfg: &Config) -> Result<Store> {
    let dir = cfg.expand_data_dir();
    std::fs::create_dir_all(&dir)?;
    Store::open(dir.join("archimede.sqlite"))
}
