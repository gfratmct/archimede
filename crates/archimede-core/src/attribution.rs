use crate::config::AgentRule;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMatch {
    pub name: String,
    pub family: String,
}

/// Catalog of known agent / harness process signatures.
#[derive(Debug, Clone, Default)]
pub struct AgentCatalog {
    rules: Vec<AgentRule>,
}

impl AgentCatalog {
    pub fn new(rules: Vec<AgentRule>) -> Self {
        Self { rules }
    }

    pub fn from_config(rules: &[AgentRule]) -> Self {
        Self {
            rules: rules.to_vec(),
        }
    }

    /// Match against process name and cmdline (case-insensitive substring).
    pub fn match_process(&self, comm: &str, cmdline: &str) -> Option<AgentMatch> {
        let hay_comm = comm.to_ascii_lowercase();
        let hay_cmd = cmdline.to_ascii_lowercase();
        for rule in &self.rules {
            for pat in &rule.match_patterns {
                let p = pat.to_ascii_lowercase();
                if hay_comm.contains(&p) || hay_cmd.contains(&p) {
                    return Some(AgentMatch {
                        name: rule.name.clone(),
                        family: rule.family.clone(),
                    });
                }
            }
        }
        None
    }

    pub fn rules(&self) -> &[AgentRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn matches_cursor() {
        let cat = AgentCatalog::from_config(&Config::default().attribution.agents);
        let m = cat
            .match_process("cursor", "/usr/share/cursor/cursor --type=renderer")
            .unwrap();
        assert_eq!(m.name, "cursor");
        assert_eq!(m.family, "coding_agent");
    }

    #[test]
    fn no_match_for_bash() {
        let cat = AgentCatalog::from_config(&Config::default().attribution.agents);
        assert!(cat.match_process("bash", "/bin/bash").is_none());
    }
}
