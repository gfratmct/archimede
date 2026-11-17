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
    /// Watch agent working directories for create / edit / delete file activity.
    #[serde(default)]
    pub file_watch: FileWatchConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWatchConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How deep to walk each watched root.
    #[serde(default = "default_file_watch_depth")]
    pub max_depth: usize,
    /// Cap emitted File events per scan to avoid log storms.
    #[serde(default = "default_file_watch_max_events")]
    pub max_events_per_scan: usize,
    /// Extra roots beyond live agent CWDs.
    #[serde(default)]
    pub roots: Vec<String>,
    /// Directory basenames skipped while walking.
    #[serde(default = "default_file_watch_ignore")]
    pub ignore_dirs: Vec<String>,
}

impl Default for FileWatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: default_file_watch_depth(),
            max_events_per_scan: default_file_watch_max_events(),
            roots: Vec::new(),
            ignore_dirs: default_file_watch_ignore(),
        }
    }
}

fn default_file_watch_depth() -> usize {
    4
}

fn default_file_watch_max_events() -> usize {
    80
}

fn default_file_watch_ignore() -> Vec<String> {
    vec![
        ".git".into(),
        "node_modules".into(),
        "target".into(),
        "dist".into(),
        "build".into(),
        ".venv".into(),
        "venv".into(),
        "__pycache__".into(),
        ".tox".into(),
        ".mypy_cache".into(),
        ".pytest_cache".into(),
        ".next".into(),
        ".cache".into(),
        "Library".into(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub poll_interval_ms: u64,
    pub bucket_secs: u64,
    pub data_dir: String,
    pub bind: String,
    pub enable_ebpf: bool,
    /// Directory with the SolidJS dashboard build (`index.html` + assets).
    /// When set (and present), the API serves it at `/`.
    #[serde(default)]
    pub dashboard_dir: Option<String>,
    /// Optional shared secret for mutating API routes (`POST /v1/clear`, and
    /// ingest when enforcement is enabled). Send as `X-Archimede-Token` or
    /// `Authorization: Bearer …`.
    #[serde(default)]
    pub api_token: Option<String>,
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

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub max_span_egress_hosts: u64,
    pub flag_on_secret_patterns: bool,
    #[serde(default = "default_true")]
    pub flag_on_prompt_injection: bool,
    #[serde(default = "default_true")]
    pub flag_on_remote_control: bool,
    /// Flag high-risk harness tools (shell/exec/curl/…) for human review even
    /// when they are not listed in `deny_tools`.
    #[serde(default = "default_true")]
    pub flag_dangerous_tools: bool,
    pub flag_on_resource_spike_pct: u64,
    /// Tools that are denied (UnauthorizedTool; may terminate when enforcement on).
    pub deny_tools: Vec<String>,
    /// Extra tool names treated as dangerous for reporting (merged with builtins).
    #[serde(default)]
    pub warn_tools: Vec<String>,
    pub allow_models: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_span_egress_hosts: 8,
            flag_on_secret_patterns: true,
            flag_on_prompt_injection: true,
            flag_on_remote_control: true,
            flag_dangerous_tools: true,
            flag_on_resource_spike_pct: 300,
            deny_tools: Vec::new(),
            warn_tools: Vec::new(),
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
            // Avoid bare "claude" — too broad; prefer explicit binary/cli names.
            match_patterns: vec![
                "claude-code".into(),
                "claude code".into(),
                "@anthropic-ai/claude".into(),
            ],
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
                dashboard_dir: Some("dashboard/dist".into()),
                api_token: None,
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
                timeout_ms: 5000,
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
            file_watch: FileWatchConfig::default(),
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

    pub fn expand_dashboard_dir(&self) -> Option<PathBuf> {
        self.daemon
            .dashboard_dir
            .as_ref()
            .map(|p| expand_tilde(p))
            .filter(|p| p.join("index.html").is_file())
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
