//! Archimede library surface for the daemon, API, and integration tests.

pub mod api;
pub mod daemon;

pub use archimede_classify as classify;
pub use archimede_collect as collect;
pub use archimede_core as core;
pub use archimede_features as features;
pub use archimede_forecast as forecast;
