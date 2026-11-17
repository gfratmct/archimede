use crate::enforcer::{Enforcer, HostEnforcer, NullEnforcer};
use crate::secrets::{looks_like_prompt_injection, looks_like_secret_exfil};
use archimede_core::{
    Config, EnforcementAction, Event, EventKind, PolicyDecision, RiskFlag, SpanKind, SpanRecord,
};
use archimede_features::FeatureBucket;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct PolicyHit {
    pub decision: PolicyDecision,
    pub alert: Event,
    pub decision_event: Event,
}

pub struct PolicyEngine {
    cfg: Arc<Config>,
    enforcer: Arc<dyn Enforcer>,
    last_fire: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl PolicyEngine {
    pub fn new(cfg: Arc<Config>) -> Self {
        let enforcer: Arc<dyn Enforcer> = if cfg.enforcement.enabled {
            Arc::new(HostEnforcer::new(&cfg.enforcement.actions))
        } else {
            Arc::new(NullEnforcer)
        };
        Self {
            cfg,
            enforcer,
            last_fire: Mutex::new(HashMap::new()),
        }
    }

    pub fn evaluate_bucket(&self, bucket: &FeatureBucket) -> Vec<PolicyHit> {
        let mut hits = Vec::new();
        for (flag, message, score) in bucket.evaluate_risks(&self.cfg) {
            if let Some(hit) = self.build_hit(
                flag,
                &message,
                score,
                Some(bucket.agent.clone()),
                None,
                None,
                None,
                preferred_action(flag),
            ) {
                hits.push(hit);
            }
        }
        if bucket.resource_spikes > 0 {
            if let Some(hit) = self.build_hit(
                RiskFlag::ResourceSpike,
                &format!(
                    "{} had {} resource spike(s) in bucket",
                    bucket.agent, bucket.resource_spikes
                ),
                0.75,
                Some(bucket.agent.clone()),
                None,
                None,
                None,
                EnforcementAction::RecordOnly,
            ) {
                hits.push(hit);
            }
        }
        if bucket.new_remotes > 0 {
            if let Some(hit) = self.build_hit(
                RiskFlag::NewRemoteHost,
                &format!(
                    "{} contacted {} new remote(s) in bucket",
                    bucket.agent, bucket.new_remotes
                ),
                0.55,
                Some(bucket.agent.clone()),
                None,
                None,
                None,
                EnforcementAction::DenyEgress,
            ) {
                hits.push(hit);
            }
        }
        hits
    }

    pub fn evaluate_span(&self, span: &SpanRecord) -> Vec<PolicyHit> {
        let mut hits = Vec::new();
        let agent = span.agent.clone();

        if matches!(span.kind, SpanKind::Tool) {
            let tool = span
                .attrs
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or(span.name.as_str());
            if self
                .cfg
                .policy
                .deny_tools
                .iter()
                .any(|d| d.eq_ignore_ascii_case(tool))
            {
                if let Some(hit) = self.build_hit(
                    RiskFlag::UnauthorizedTool,
                    &format!("denied tool `{tool}` used by harness"),
                    0.9,
                    agent.clone(),
                    None,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::TerminateProcess,
                ) {
                    hits.push(hit);
                }
            }
        }

        if matches!(span.kind, SpanKind::Llm) {
            if let Some(model) = span.model.as_deref() {
                if !self.cfg.policy.allow_models.is_empty()
                    && !self
                        .cfg
                        .policy
                        .allow_models
                        .iter()
                        .any(|m| m.eq_ignore_ascii_case(model))
                {
                    if let Some(hit) = self.build_hit(
                        RiskFlag::PolicyDeny,
                        &format!("model `{model}` not in allow_models"),
                        0.8,
                        agent.clone(),
                        None,
                        Some(span.trace_id.clone()),
                        Some(span.span_id.clone()),
                        EnforcementAction::RecordOnly,
                    ) {
                        hits.push(hit);
                    }
                }
            }
        }

        if let Some(hosts) = span.attrs.get("egress_hosts").and_then(|v| v.as_array()) {
            if hosts.len() as u64 > self.cfg.policy.max_span_egress_hosts {
                if let Some(hit) = self.build_hit(
                    RiskFlag::HighEgress,
                    &format!(
                        "span listed {} egress hosts (max {})",
                        hosts.len(),
                        self.cfg.policy.max_span_egress_hosts
                    ),
                    0.7,
                    agent.clone(),
                    None,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::DenyEgress,
                ) {
                    hits.push(hit);
                }
            }
        }

        if self.cfg.policy.flag_on_secret_patterns {
            let blob = format!(
                "{} {}",
                span.input_summary.as_deref().unwrap_or(""),
                span.output_summary.as_deref().unwrap_or("")
            );
            if looks_like_secret_exfil(&blob) {
                if let Some(hit) = self.build_hit(
                    RiskFlag::SecretExfilHint,
                    "span text matched secret-like patterns",
                    0.85,
                    agent.clone(),
                    None,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::TerminateProcess,
                ) {
                    hits.push(hit);
                }
            }
            if looks_like_prompt_injection(&blob) {
                if let Some(hit) = self.build_hit(
                    RiskFlag::PromptInjectionHint,
                    "span text matched prompt-injection heuristics",
                    0.65,
                    agent.clone(),
                    None,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::RecordOnly,
                ) {
                    hits.push(hit);
                }
            }
        }

        hits
    }

    #[allow(clippy::too_many_arguments)]
    fn build_hit(
        &self,
        flag: RiskFlag,
        reason: &str,
        score: f32,
        agent: Option<String>,
        pid: Option<i32>,
        trace_id: Option<String>,
        span_id: Option<String>,
        action: EnforcementAction,
    ) -> Option<PolicyHit> {
        let key = format!(
            "{}:{}:{}",
            agent.as_deref().unwrap_or("-"),
            flag.as_str(),
            trace_id.as_deref().unwrap_or("-")
        );
        if !self.allow_fire(&key) {
            return None;
        }

        let action = if self.cfg.enforcement.enabled
            && self
                .cfg
                .enforcement
                .actions
                .iter()
                .any(|a| a == action.as_str())
        {
            action
        } else if matches!(action, EnforcementAction::RecordOnly) {
            EnforcementAction::RecordOnly
        } else if self.cfg.enforcement.enabled {
            // Requested action not allowlisted → still record.
            EnforcementAction::RecordOnly
        } else {
            EnforcementAction::RecordOnly
        };

        let enforced = if self.cfg.enforcement.enabled
            && !matches!(action, EnforcementAction::RecordOnly)
        {
            self.enforcer.apply(action, pid, reason)
        } else {
            self.enforcer
                .apply(EnforcementAction::RecordOnly, pid, reason);
            false
        };

        let decision = PolicyDecision {
            flag,
            action,
            reason: reason.to_string(),
            agent: agent.clone(),
            pid,
            trace_id,
            span_id,
            score,
            enforced,
        };

        let alert = Event::new(
            "policy",
            EventKind::Alert {
                flag,
                agent: agent.clone(),
                message: reason.to_string(),
                score,
            },
        );
        let decision_event = Event::new("policy", EventKind::PolicyDecision(decision.clone()));
        Some(PolicyHit {
            decision,
            alert,
            decision_event,
        })
    }

    fn allow_fire(&self, key: &str) -> bool {
        let cool = self.cfg.enforcement.cool_down_secs.max(1) as i64;
        let mut map = self.last_fire.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        if let Some(prev) = map.get(key) {
            if (now - *prev).num_seconds() < cool {
                return false;
            }
        }
        map.insert(key.to_string(), now);
        true
    }
}

fn preferred_action(flag: RiskFlag) -> EnforcementAction {
    match flag {
        RiskFlag::MassDelete
        | RiskFlag::UnknownBinaryStorm
        | RiskFlag::SecretExfilHint
        | RiskFlag::UnauthorizedTool
        | RiskFlag::ShadowBinary => EnforcementAction::TerminateProcess,
        RiskFlag::HighEgress | RiskFlag::NewRemoteHost | RiskFlag::SuspiciousDns => {
            EnforcementAction::DenyEgress
        }
        _ => EnforcementAction::RecordOnly,
    }
}
