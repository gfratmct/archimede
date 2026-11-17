//! Archimede core: typed events, bus, SQLite store, agent attribution.

pub mod attribution;
pub mod bus;
pub mod config;
pub mod dedupe;
pub mod event;
pub mod store;

pub use attribution::{AgentCatalog, AgentMatch};
pub use bus::EventBus;
pub use config::{expand_tilde, Config, EnforcementConfig, FileWatchConfig, PolicyConfig};
pub use dedupe::{fingerprint_piece, normalize_piece, stable_event_id};
pub use event::{
    BehaviorLabel, EnforcementAction, Event, EventKind, FileOp, NetworkMeta, PolicyDecision,
    ProcessSnapshot, ResourceDelta, RiskEvidence, RiskFlag, SessionHint, SpanKind, SpanRecord,
    TokenUsage, TraceRecord,
};
pub use store::{
    AlertRow, EnforcementRow, FlagRow, MetricPoint, StatsSummary, Store, TraceTree,
};
