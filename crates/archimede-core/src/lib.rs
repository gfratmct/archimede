//! Archimede core: typed events, bus, SQLite store, agent attribution.

pub mod attribution;
pub mod bus;
pub mod config;
pub mod event;
pub mod store;

pub use attribution::{AgentCatalog, AgentMatch};
pub use bus::EventBus;
pub use config::Config;
pub use event::{
    BehaviorLabel, Event, EventKind, FileOp, NetworkMeta, ProcessSnapshot, RiskFlag, SessionHint,
};
pub use store::Store;
