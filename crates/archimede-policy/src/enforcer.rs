use archimede_core::EnforcementAction;
use tracing::{info, warn};

pub trait Enforcer: Send + Sync {
    fn apply(&self, action: EnforcementAction, pid: Option<i32>, reason: &str) -> bool;
}

/// No-op enforcer used when enforcement is disabled (still audit via PolicyDecision).
pub struct NullEnforcer;

impl Enforcer for NullEnforcer {
    fn apply(&self, action: EnforcementAction, pid: Option<i32>, reason: &str) -> bool {
        info!(
            action = action.as_str(),
            ?pid,
            reason,
            "enforcement disabled; recording decision only"
        );
        false
    }
}

/// Unix process terminator; deny_egress is stubbed (audit only).
pub struct HostEnforcer {
    allow_terminate: bool,
    allow_deny_egress: bool,
}

impl HostEnforcer {
    pub fn new(allowed_actions: &[String]) -> Self {
        Self {
            allow_terminate: allowed_actions.iter().any(|a| a == "terminate_process"),
            allow_deny_egress: allowed_actions.iter().any(|a| a == "deny_egress"),
        }
    }
}

impl Enforcer for HostEnforcer {
    fn apply(&self, action: EnforcementAction, pid: Option<i32>, reason: &str) -> bool {
        match action {
            EnforcementAction::RecordOnly => false,
            EnforcementAction::TerminateProcess => {
                if !self.allow_terminate {
                    warn!(reason, "terminate_process not in enforcement.actions allowlist");
                    return false;
                }
                let Some(pid) = pid else {
                    warn!(reason, "terminate_process requested without pid");
                    return false;
                };
                terminate_pid(pid, reason)
            }
            EnforcementAction::DenyEgress => {
                if !self.allow_deny_egress {
                    warn!(reason, "deny_egress not in enforcement.actions allowlist");
                    return false;
                }
                info!(
                    ?pid,
                    reason,
                    "deny_egress stub: logged only (firewall hooks not yet wired)"
                );
                false
            }
        }
    }
}

fn terminate_pid(pid: i32, reason: &str) -> bool {
    if pid <= 1 {
        warn!(pid, reason, "refusing to signal init/system pid");
        return false;
    }
    #[cfg(unix)]
    {
        // SIGTERM then brief wait pattern: send SIGTERM; caller may retry with SIGKILL later.
        let term = unsafe { libc::kill(pid, libc::SIGTERM) };
        if term == 0 {
            info!(pid, reason, "sent SIGTERM");
            return true;
        }
        let err = std::io::Error::last_os_error();
        warn!(pid, reason, error = %err, "SIGTERM failed; trying SIGKILL");
        let kill = unsafe { libc::kill(pid, libc::SIGKILL) };
        if kill == 0 {
            info!(pid, reason, "sent SIGKILL");
            true
        } else {
            warn!(pid, reason, error = %std::io::Error::last_os_error(), "SIGKILL failed");
            false
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, reason);
        warn!("process termination not supported on this platform");
        false
    }
}
