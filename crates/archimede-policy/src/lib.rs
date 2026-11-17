//! Security policy evaluation and optional host enforcement.

mod enforcer;
mod engine;
mod secrets;

pub use enforcer::{Enforcer, HostEnforcer, NullEnforcer};
pub use engine::{PolicyEngine, PolicyHit};
pub use secrets::{
    is_dangerous_tool, looks_like_prompt_injection, looks_like_remote_control,
    looks_like_secret_exfil, redact_secrets, scan_text_threats, TextThreat,
};
