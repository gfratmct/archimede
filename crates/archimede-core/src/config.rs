use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub attribution: AttributionConfig,
    pub session_logs: SessionLogsConfig,
    pub classify: ClassifyConfig,
    pub forecast: ForecastConfig,
    pub alerts: AlertsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub poll_interval_ms: u64,
    pub bucket_secs: u64,
    pub data_dir: String,
    pub bind: String,
    pub enable_ebpf: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionConfig {
    pub agents: Vec<AgentRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRule {
    pub name: String,
    pub family: String,
    #[serde(rename = "match")]
    pub match_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLogsConfig {
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout_ms: u64,
    pub fallback_rules: bool,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastConfig {
    pub model_size: String,
    pub context_len: usize,
    pub horizon: usize,
    pub onnx_path: Option<String>,
    pub sidecar_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    pub egress_bytes_per_bucket: u64,
    pub exec_rate_per_bucket: u64,
    pub delete_rate_per_bucket: u64,
    pub risk_score_threshold: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig {
                poll_interval_ms: 2000,
                bucket_secs: 30,
                data_dir: "~/.local/share/archimede".into(),
                bind: "127.0.0.1:7432".into(),
                enable_ebpf: false,
            },
            attribution: AttributionConfig {
                agents: vec![
                    AgentRule {
                        name: "cursor".into(),
                        family: "coding_agent".into(),
                        match_patterns: vec!["cursor".into(), "Cursor".into()],
                    },
                    AgentRule {
                        name: "claude-code".into(),
                        family: "coding_agent".into(),
                        match_patterns: vec!["claude".into(), "claude-code".into()],
                    },
                    AgentRule {
                        name: "copilot".into(),
                        family: "coding_agent".into(),
                        match_patterns: vec!["copilot".into()],
                    },
                    AgentRule {
                        name: "openclaw".into(),
                        family: "harness".into(),
                        match_patterns: vec!["openclaw".into()],
                    },
                    AgentRule {
                        name: "hermes".into(),
                        family: "harness".into(),
                        match_patterns: vec!["hermes".into()],
                    },
                    AgentRule {
                        name: "pi".into(),
                        family: "harness".into(),
                        match_patterns: vec!["pi-agent".into(), "pi_agent".into()],
                    },
                    AgentRule {
                        name: "ollama".into(),
                        family: "local_llm".into(),
                        match_patterns: vec!["ollama".into()],
                    },
                    AgentRule {
                        name: "llama-server".into(),
                        family: "local_llm".into(),
                        match_patterns: vec!["llama-server".into(), "llama.cpp".into()],
                    },
                ],
            },
            session_logs: SessionLogsConfig {
                paths: vec!["~/.cursor".into(), "~/.claude".into()],
            },
            classify: ClassifyConfig {
                endpoint: "http://127.0.0.1:8017/v1/systemone".into(),
                model: "jev-latest".into(),
                timeout_ms: 500,
                fallback_rules: true,
                labels: crate::event::BehaviorLabel::all()
                    .iter()
                    .map(|l| l.as_str().to_string())
                    .collect(),
            },
            forecast: ForecastConfig {
                model_size: "5M".into(),
                context_len: 256,
                horizon: 16,
                onnx_path: None,
                sidecar_url: None,
            },
            alerts: AlertsConfig {
                egress_bytes_per_bucket: 50_000_000,
                exec_rate_per_bucket: 40,
                delete_rate_per_bucket: 20,
                risk_score_threshold: 0.7,
            },
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading config {}", path.as_ref().display()))?;
        let cfg: Config = serde_yaml::from_str(&raw).context("parsing config YAML")?;
        Ok(cfg)
    }

    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => Self::load(p),
            Some(_) => Ok(Self::default()),
            None => {
                let candidates = [
                    PathBuf::from("configs/archimede.yaml"),
                    PathBuf::from("/etc/archimede/archimede.yaml"),
                    dirs::config_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join("archimede/archimede.yaml"),
                ];
                for c in candidates {
                    if c.exists() {
                        return Self::load(&c);
                    }
                }
                Ok(Self::default())
            }
        }
    }

    pub fn expand_data_dir(&self) -> PathBuf {
        expand_tilde(&self.daemon.data_dir)
    }
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roundtrip_yaml() {
        let cfg = Config::default();
        let y = serde_yaml::to_string(&cfg).unwrap();
        let back: Config = serde_yaml::from_str(&y).unwrap();
        assert_eq!(back.daemon.bind, cfg.daemon.bind);
        assert!(!back.attribution.agents.is_empty());
        assert_eq!(
            back.attribution.agents[0].match_patterns,
            cfg.attribution.agents[0].match_patterns
        );
    }

    #[test]
    fn loads_repo_config() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../configs/archimede.yaml");
        if path.exists() {
            let cfg = Config::load(&path).unwrap();
            assert_eq!(cfg.daemon.bind, "127.0.0.1:7432");
        }
    }
}
