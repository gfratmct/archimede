//! Archimede core: typed events, bus, SQLite store, agent attribution.

pub mod attribution;
pub mod bus;
pub mod config;
pub mod event;
pub mod store;

pub use attribution::{AgentCatalog, AgentMatch};
pub use bus::EventBus;
pub use config::{Config, EnforcementConfig, PolicyConfig};
pub use event::{
    BehaviorLabel, EnforcementAction, Event, EventKind, FileOp, NetworkMeta, PolicyDecision,
    ProcessSnapshot, ResourceDelta, RiskFlag, SessionHint, SpanKind, SpanRecord, TokenUsage,
    TraceRecord,
};
pub use store::{
    AlertRow, EnforcementRow, FlagRow, MetricPoint, StatsSummary, Store, TraceTree,
};
