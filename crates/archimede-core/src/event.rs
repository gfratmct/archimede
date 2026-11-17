use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Canonical behavior labels used by System-One classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorLabel {
    Idle,
    Planning,
    Coding,
    Testing,
    ShellTools,
    Browsing,
    LlmWait,
    RiskyEgress,
}

impl BehaviorLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Planning => "planning",
            Self::Coding => "coding",
            Self::Testing => "testing",
            Self::ShellTools => "shell_tools",
            Self::Browsing => "browsing",
            Self::LlmWait => "llm_wait",
            Self::RiskyEgress => "risky_egress",
        }
    }

    pub fn all() -> &'static [BehaviorLabel] {
        &[
            Self::Idle,
            Self::Planning,
            Self::Coding,
            Self::Testing,
            Self::ShellTools,
            Self::Browsing,
            Self::LlmWait,
            Self::RiskyEgress,
        ]
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "idle" => Some(Self::Idle),
            "planning" => Some(Self::Planning),
            "coding" => Some(Self::Coding),
            "testing" => Some(Self::Testing),
            "shell_tools" => Some(Self::ShellTools),
            "browsing" => Some(Self::Browsing),
            "llm_wait" => Some(Self::LlmWait),
            "risky_egress" => Some(Self::RiskyEgress),
            _ => None,
        }
    }
}

impl std::fmt::Display for BehaviorLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    HighEgress,
    HighExecRate,
    MassDelete,
    UnknownBinaryStorm,
    SuspiciousDns,
    ElevatedRiskScore,
    PromptInjectionHint,
    SecretExfilHint,
    UnauthorizedTool,
    ShadowBinary,
    ResourceSpike,
    NewRemoteHost,
    PolicyDeny,
}

impl RiskFlag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HighEgress => "high_egress",
            Self::HighExecRate => "high_exec_rate",
            Self::MassDelete => "mass_delete",
            Self::UnknownBinaryStorm => "unknown_binary_storm",
            Self::SuspiciousDns => "suspicious_dns",
            Self::ElevatedRiskScore => "elevated_risk_score",
            Self::PromptInjectionHint => "prompt_injection_hint",
            Self::SecretExfilHint => "secret_exfil_hint",
            Self::UnauthorizedTool => "unauthorized_tool",
            Self::ShadowBinary => "shadow_binary",
            Self::ResourceSpike => "resource_spike",
            Self::NewRemoteHost => "new_remote_host",
            Self::PolicyDeny => "policy_deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Llm,
    Tool,
    Agent,
    Chain,
    Retriever,
    Custom,
}

impl SpanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::Tool => "tool",
            Self::Agent => "agent",
            Self::Chain => "chain",
            Self::Retriever => "retriever",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub total: Option<u64>,
}

/// Langfuse-shaped span observation from a custom harness / LLM SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanRecord {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: SpanKind,
    pub agent: Option<String>,
    pub harness: Option<String>,
    pub model: Option<String>,
    pub input_summary: Option<String>,
    pub output_summary: Option<String>,
    #[serde(default)]
    pub attrs: JsonValue,
    pub start_ts: DateTime<Utc>,
    pub end_ts: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub token_usage: Option<TokenUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub trace_id: String,
    pub name: Option<String>,
    pub agent: Option<String>,
    pub harness: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub metadata: JsonValue,
    pub start_ts: DateTime<Utc>,
    pub end_ts: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDelta {
    pub pid: i32,
    pub agent: Option<String>,
    pub cpu_delta: f32,
    pub rss_delta: i64,
    pub fd_count: Option<u64>,
    pub thread_count: Option<u64>,
    pub change_reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    RecordOnly,
    TerminateProcess,
    DenyEgress,
}

impl EnforcementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecordOnly => "record_only",
            Self::TerminateProcess => "terminate_process",
            Self::DenyEgress => "deny_egress",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "record_only" => Some(Self::RecordOnly),
            "terminate_process" => Some(Self::TerminateProcess),
            "deny_egress" => Some(Self::DenyEgress),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub flag: RiskFlag,
    pub action: EnforcementAction,
    pub reason: String,
    pub agent: Option<String>,
    pub pid: Option<i32>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub score: f32,
    pub enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessSnapshot(ProcessSnapshot),
    Exec {
        pid: i32,
        ppid: i32,
        comm: String,
        argv_summary: String,
    },
    Connect {
        pid: i32,
        dest: String,
        port: u16,
        sni: Option<String>,
    },
    Dns {
        pid: Option<i32>,
        query: String,
    },
    File(FileOp),
    NetworkMeta(NetworkMeta),
    Session(SessionHint),
    Span(SpanRecord),
    ResourceDelta(ResourceDelta),
    PolicyDecision(PolicyDecision),
    Classification {
        agent: String,
        label: BehaviorLabel,
        confidence: f32,
        source: String,
    },
    Forecast {
        metric: String,
        horizon_steps: usize,
        predicted: Vec<f32>,
        lower: Vec<f32>,
        upper: Vec<f32>,
    },
    Alert {
        flag: RiskFlag,
        agent: Option<String>,
        message: String,
        score: f32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub cmdline: String,
    pub cwd: Option<String>,
    pub rss_bytes: u64,
    pub cpu_pct: f32,
    pub agent: Option<String>,
    pub family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOp {
    pub pid: i32,
    pub path: String,
    pub op: String, // open|write|unlink|rename
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMeta {
    pub pid: i32,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHint {
    pub agent: String,
    pub path: String,
    pub kind: String, // transcript|tool_call|message
    pub summary: String,
}

/// Top-level envelope for every observation flowing through Archimede.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    pub source: String,
    pub agent: Option<String>,
    pub kind: EventKind,
}

impl Event {
    pub fn new(source: impl Into<String>, kind: EventKind) -> Self {
        let agent = match &kind {
            EventKind::ProcessSnapshot(p) => p.agent.clone(),
            EventKind::File(f) => f.agent.clone(),
            EventKind::NetworkMeta(n) => n.agent.clone(),
            EventKind::Session(s) => Some(s.agent.clone()),
            EventKind::Span(s) => s.agent.clone(),
            EventKind::ResourceDelta(r) => r.agent.clone(),
            EventKind::PolicyDecision(p) => p.agent.clone(),
            EventKind::Classification { agent, .. } => Some(agent.clone()),
            EventKind::Alert { agent, .. } => agent.clone(),
            EventKind::Exec { .. }
            | EventKind::Connect { .. }
            | EventKind::Dns { .. }
            | EventKind::Forecast { .. } => None,
        };
        Self {
            id: Uuid::new_v4(),
            ts: Utc::now(),
            source: source.into(),
            agent,
            kind,
        }
    }
}
