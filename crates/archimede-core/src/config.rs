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
    #[serde(default)]
    pub enforcement: EnforcementConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    /// When false (default), Archimede only observes and alerts.
    pub enabled: bool,
    /// Allowlisted actions that may actually run when enabled.
    pub actions: Vec<String>,
    pub cool_down_secs: u64,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            actions: vec!["terminate_process".into()],
            cool_down_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub max_span_egress_hosts: u64,
    pub flag_on_secret_patterns: bool,
    pub flag_on_resource_spike_pct: u64,
    pub deny_tools: Vec<String>,
    pub allow_models: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_span_egress_hosts: 8,
            flag_on_secret_patterns: true,
            flag_on_resource_spike_pct: 300,
            deny_tools: Vec::new(),
            allow_models: Vec::new(),
        }
    }
}

fn default_agents() -> Vec<AgentRule> {
    vec![
        // coding agents
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
            match_patterns: vec!["copilot".into(), "github-copilot".into()],
        },
        AgentRule {
            name: "windsurf".into(),
            family: "coding_agent".into(),
            match_patterns: vec!["windsurf".into(), "Cascade".into()],
        },
        AgentRule {
            name: "aider".into(),
            family: "coding_agent".into(),
            match_patterns: vec!["aider".into()],
        },
        AgentRule {
            name: "continue".into(),
            family: "coding_agent".into(),
            match_patterns: vec!["continue-server".into(), "continue.dev".into()],
        },
        AgentRule {
            name: "zed-agent".into(),
            family: "coding_agent".into(),
            match_patterns: vec!["zed-agent".into(), "zed ".into()],
        },
        AgentRule {
            name: "amp".into(),
            family: "coding_agent".into(),
            match_patterns: vec!["amp-cli".into(), "sourcegraph-amp".into()],
        },
        AgentRule {
            name: "codex".into(),
            family: "coding_agent".into(),
            match_patterns: vec!["codex".into(), "openai-codex".into()],
        },
        // harnesses
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
            name: "langchain".into(),
            family: "harness".into(),
            match_patterns: vec!["langchain".into(), "langgraph".into()],
        },
        AgentRule {
            name: "llama-index".into(),
            family: "harness".into(),
            match_patterns: vec!["llama-index".into(), "llamaindex".into()],
        },
        AgentRule {
            name: "crewai".into(),
            family: "harness".into(),
            match_patterns: vec!["crewai".into()],
        },
        AgentRule {
            name: "autogen".into(),
            family: "harness".into(),
            match_patterns: vec!["autogen".into(), "ag2".into()],
        },
        AgentRule {
            name: "semantic-kernel".into(),
            family: "harness".into(),
            match_patterns: vec!["semantic-kernel".into(), "semantickernel".into()],
        },
        AgentRule {
            name: "dspy".into(),
            family: "harness".into(),
            match_patterns: vec!["dspy".into()],
        },
        AgentRule {
            name: "haystack".into(),
            family: "harness".into(),
            match_patterns: vec!["haystack".into()],
        },
        // local LLMs
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
        AgentRule {
            name: "vllm".into(),
            family: "local_llm".into(),
            match_patterns: vec!["vllm".into()],
        },
        AgentRule {
            name: "lmstudio".into(),
            family: "local_llm".into(),
            match_patterns: vec!["lmstudio".into(), "LM Studio".into()],
        },
        AgentRule {
            name: "kobold".into(),
            family: "local_llm".into(),
            match_patterns: vec!["koboldcpp".into(), "kobold".into()],
        },
        AgentRule {
            name: "text-generation-webui".into(),
            family: "local_llm".into(),
            match_patterns: vec!["text-generation-webui".into(), "oobabooga".into()],
        },
        AgentRule {
            name: "mlx".into(),
            family: "local_llm".into(),
            match_patterns: vec!["mlx_lm".into(), "mlx-lm".into()],
        },
        // cloud bridges (process/cmdline hints)
        AgentRule {
            name: "openai-node".into(),
            family: "cloud_bridge".into(),
            match_patterns: vec!["openai".into()],
        },
        AgentRule {
            name: "anthropic".into(),
            family: "cloud_bridge".into(),
            match_patterns: vec!["anthropic".into()],
        },
        AgentRule {
            name: "gemini".into(),
            family: "cloud_bridge".into(),
            match_patterns: vec!["gemini".into(), "google-generativeai".into()],
        },
    ]
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
                agents: default_agents(),
            },
            session_logs: SessionLogsConfig {
                paths: vec![
                    "~/.cursor".into(),
                    "~/.claude".into(),
                    "~/.config/github-copilot".into(),
                    "~/.codex".into(),
                    "~/.aider".into(),
                    "~/.continue".into(),
                    "~/.codeium".into(),
                ],
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
            enforcement: EnforcementConfig::default(),
            policy: PolicyConfig::default(),
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
        assert!(!back.enforcement.enabled);
        assert_eq!(
            back.attribution.agents[0].match_patterns,
            cfg.attribution.agents[0].match_patterns
        );
    }

    #[test]
    fn loads_repo_config() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/archimede.yaml");
        if path.exists() {
            let cfg = Config::load(&path).unwrap();
            assert_eq!(cfg.daemon.bind, "127.0.0.1:7432");
            assert!(!cfg.enforcement.enabled);
        }
    }
}
