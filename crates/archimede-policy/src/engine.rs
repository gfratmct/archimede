use crate::enforcer::{Enforcer, HostEnforcer, NullEnforcer};
use crate::secrets::{
    is_dangerous_tool, looks_like_prompt_injection, looks_like_remote_control,
    looks_like_secret_exfil, redact_secrets,
};
use archimede_core::{
    stable_event_id, Config, EnforcementAction, Event, EventKind, PolicyDecision, RiskEvidence,
    RiskFlag, SessionHint, SpanKind, SpanRecord,
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
    /// Fingerprints of pieces already shown to a human (agent+flag+snippet).
    seen_pieces: Mutex<HashMap<String, DateTime<Utc>>>,
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
            seen_pieces: Mutex::new(HashMap::new()),
        }
    }

    pub fn evaluate_bucket(&self, bucket: &FeatureBucket) -> Vec<PolicyHit> {
        let mut hits = Vec::new();
        // No live activity → nothing actionable for a human to validate.
        if !bucket.is_active() {
            return hits;
        }
        let mut base = bucket.evidence_snapshot(None, None);
        let snippets = bucket.risky_snippets();
        if !snippets.is_empty() {
            base.text_snippets = snippets;
        }
        for (flag, message, score) in bucket.evaluate_risks(&self.cfg) {
            if let Some(hit) = self.build_hit(
                flag,
                &message,
                score,
                Some(bucket.agent.clone()),
                base.pid,
                None,
                None,
                preferred_action(flag),
                base.clone(),
                Some(&message),
            ) {
                hits.push(hit);
            }
        }
        if bucket.resource_spikes > 0 {
            let msg = format!(
                "{} had {} resource spike(s) in bucket",
                bucket.agent, bucket.resource_spikes
            );
            if let Some(hit) = self.build_hit(
                RiskFlag::ResourceSpike,
                &msg,
                0.75,
                Some(bucket.agent.clone()),
                base.pid,
                None,
                None,
                EnforcementAction::RecordOnly,
                base.clone(),
                Some(&msg),
            ) {
                hits.push(hit);
            }
        }
        if bucket.new_remotes > 0 {
            let msg = format!(
                "{} contacted {} new remote(s) in bucket",
                bucket.agent, bucket.new_remotes
            );
            if let Some(hit) = self.build_hit(
                RiskFlag::NewRemoteHost,
                &msg,
                0.55,
                Some(bucket.agent.clone()),
                base.pid,
                None,
                None,
                EnforcementAction::DenyEgress,
                base.clone(),
                Some(&msg),
            ) {
                hits.push(hit);
            }
        }

        // Prompt-injection / remote-control on bucket command + text evidence.
        let mut corpus = String::new();
        for cmd in &bucket.recent_commands {
            corpus.push_str(cmd);
            corpus.push('\n');
        }
        for text in &bucket.recent_text {
            corpus.push_str(text);
            corpus.push('\n');
        }
        hits.extend(self.evaluate_text_blob(
            &corpus,
            Some(bucket.agent.clone()),
            base.pid,
            None,
            None,
            base,
            "bucket",
        ));

        hits
    }

    /// Fast path for exec argv (reverse shells often appear before bucket flush).
    pub fn evaluate_exec_argv(
        &self,
        blob: &str,
        agent: Option<String>,
        pid: Option<i32>,
    ) -> Vec<PolicyHit> {
        let evidence = RiskEvidence {
            pid,
            ppid: None,
            process_name: None,
            process_path: None,
            cwd: None,
            commands: vec![blob.to_string()],
            behavior: Some("exec".into()),
            behavior_confidence: None,
            risk_score: None,
            text_snippets: vec![blob.to_string()],
            network_requests: Vec::new(),
            remotes: Vec::new(),
            binaries: Vec::new(),
            files: Vec::new(),
            trace_id: None,
            span_id: None,
            request_summary: Some(blob.to_string()),
            response_summary: None,
        };
        self.evaluate_text_blob(blob, agent, pid, None, None, evidence, "exec")
    }

    /// Scan session-log excerpts (transcripts / tool calls) for injection & remote control.
    pub fn evaluate_session(&self, session: &SessionHint) -> Vec<PolicyHit> {
        let evidence = RiskEvidence {
            pid: None,
            ppid: None,
            process_name: None,
            process_path: Some(session.path.clone()),
            cwd: None,
            commands: Vec::new(),
            behavior: Some(format!("session:{}", session.kind)),
            behavior_confidence: None,
            risk_score: None,
            text_snippets: vec![session.summary.clone()],
            network_requests: Vec::new(),
            remotes: Vec::new(),
            binaries: Vec::new(),
            files: Vec::new(),
            trace_id: None,
            span_id: None,
            request_summary: Some(session.summary.clone()),
            response_summary: None,
        };
        self.evaluate_text_blob(
            &session.summary,
            Some(session.agent.clone()),
            None,
            None,
            None,
            evidence,
            "session",
        )
    }

    /// Classifier-driven elevated risk: only when agent is active, risk crosses
    /// threshold, and there is a concrete snippet for a human to review.
    pub fn evaluate_classification_risk(
        &self,
        bucket: &FeatureBucket,
        label: &str,
        confidence: f32,
        risk_score: f32,
        top: &str,
    ) -> Option<PolicyHit> {
        if !bucket.is_active() {
            return None;
        }
        if label != "risky_egress" {
            return None;
        }
        if risk_score < self.cfg.alerts.risk_score_threshold {
            return None;
        }
        let snippets = bucket.risky_snippets();
        // Require something concrete for human validation (or real egress).
        if snippets.is_empty() && bucket.egress_proxy_score < 1.0 && bucket.shell_hints == 0 {
            return None;
        }
        let mut evidence = bucket.evidence_snapshot(
            Some((label.to_string(), confidence)),
            Some(risk_score),
        );
        if !snippets.is_empty() {
            evidence.text_snippets = snippets.clone();
        }
        let snippet_preview = snippets
            .first()
            .cloned()
            .or_else(|| {
                bucket
                    .recent_network
                    .last()
                    .map(|n| format!("net: {n}"))
            })
            .unwrap_or_else(|| "no snippet".into());
        let message = format!(
            "{agent} risky_egress · risk={:.0}% conf={:.0}% (threshold {:.0}%) · {snippet_preview} · top=[{top}]",
            risk_score * 100.0,
            confidence * 100.0,
            self.cfg.alerts.risk_score_threshold * 100.0,
            agent = bucket.agent,
        );
        self.build_hit(
            RiskFlag::ElevatedRiskScore,
            &message,
            risk_score,
            Some(bucket.agent.clone()),
            evidence.pid,
            None,
            None,
            EnforcementAction::RecordOnly,
            evidence,
            Some(&message),
        )
    }

    pub fn evaluate_span(&self, span: &SpanRecord) -> Vec<PolicyHit> {
        let mut hits = Vec::new();
        let agent = span.agent.clone();
        let evidence = evidence_from_span(span);
        // Never enforce using client-supplied span attrs.pid — that is attacker-
        // controlled via POST /v1/spans. Host collectors pass trusted PIDs.
        let enforce_pid: Option<i32> = None;

        if matches!(span.kind, SpanKind::Tool) {
            let tool = span
                .attrs
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or(span.name.as_str());
            let tool_input = span.input_summary.as_deref().unwrap_or("");
            let denied = self
                .cfg
                .policy
                .deny_tools
                .iter()
                .any(|d| d.eq_ignore_ascii_case(tool));
            if denied {
                let mut ev = evidence.clone();
                ev.commands.insert(0, format!("tool:{tool}"));
                if !tool_input.is_empty() {
                    ev.text_snippets.insert(
                        0,
                        format!(
                            "tool-args: {}",
                            redact_secrets(&truncate_snippet(tool_input, 200))
                        ),
                    );
                }
                let msg = format!(
                    "denied tool `{tool}` used by harness · {}",
                    redact_secrets(&truncate_snippet(tool_input, 120))
                );
                if let Some(hit) = self.build_hit(
                    RiskFlag::UnauthorizedTool,
                    &msg,
                    0.9,
                    agent.clone(),
                    enforce_pid,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::TerminateProcess,
                    ev,
                    Some(&msg),
                ) {
                    hits.push(hit);
                }
            } else if self.cfg.policy.flag_dangerous_tools
                && is_dangerous_tool(tool, &self.cfg.policy.warn_tools)
            {
                let mut ev = evidence.clone();
                ev.commands.insert(0, format!("tool:{tool}"));
                if !tool_input.is_empty() {
                    ev.text_snippets.insert(
                        0,
                        format!(
                            "tool-args: {}",
                            redact_secrets(&truncate_snippet(tool_input, 200))
                        ),
                    );
                }
                let msg = format!(
                    "dangerous tool `{tool}` invoked · {}",
                    redact_secrets(&truncate_snippet(
                        if tool_input.is_empty() { tool } else { tool_input },
                        120
                    ))
                );
                if let Some(hit) = self.build_hit(
                    RiskFlag::UnauthorizedTool,
                    &msg,
                    0.7,
                    agent.clone(),
                    enforce_pid,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::RecordOnly,
                    ev,
                    Some(&msg),
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
                    let msg = format!("model `{model}` not in allow_models");
                    if let Some(hit) = self.build_hit(
                        RiskFlag::PolicyDeny,
                        &msg,
                        0.8,
                        agent.clone(),
                        enforce_pid,
                        Some(span.trace_id.clone()),
                        Some(span.span_id.clone()),
                        EnforcementAction::RecordOnly,
                        evidence.clone(),
                        Some(&msg),
                    ) {
                        hits.push(hit);
                    }
                }
            }
        }

        if let Some(hosts) = span.attrs.get("egress_hosts").and_then(|v| v.as_array()) {
            if hosts.len() as u64 > self.cfg.policy.max_span_egress_hosts {
                let msg = format!(
                    "span listed {} egress hosts (max {})",
                    hosts.len(),
                    self.cfg.policy.max_span_egress_hosts
                );
                if let Some(hit) = self.build_hit(
                    RiskFlag::HighEgress,
                    &msg,
                    0.7,
                    agent.clone(),
                    enforce_pid,
                    Some(span.trace_id.clone()),
                    Some(span.span_id.clone()),
                    EnforcementAction::DenyEgress,
                    evidence.clone(),
                    Some(&msg),
                ) {
                    hits.push(hit);
                }
            }
        }

        let mut blob = format!(
            "{} {}\n{}",
            span.input_summary.as_deref().unwrap_or(""),
            span.output_summary.as_deref().unwrap_or(""),
            span.name
        );
        if let Some(cmd) = span.attrs.get("command").and_then(|v| v.as_str()) {
            blob.push('\n');
            blob.push_str(cmd);
        }
        if let Some(argv) = span.attrs.get("argv").and_then(|v| v.as_str()) {
            blob.push('\n');
            blob.push_str(argv);
        }

        hits.extend(self.evaluate_text_blob(
            &blob,
            agent,
            enforce_pid,
            Some(span.trace_id.clone()),
            Some(span.span_id.clone()),
            evidence,
            "span",
        ));

        hits
    }

    fn evaluate_text_blob(
        &self,
        blob: &str,
        agent: Option<String>,
        pid: Option<i32>,
        trace_id: Option<String>,
        span_id: Option<String>,
        evidence: RiskEvidence,
        source: &str,
    ) -> Vec<PolicyHit> {
        let mut hits = Vec::new();
        if blob.trim().is_empty() {
            return hits;
        }

        if self.cfg.policy.flag_on_secret_patterns && looks_like_secret_exfil(blob) {
            let mut ev = evidence.clone();
            let safe = redact_secrets(&truncate_snippet(blob, 200));
            ev.text_snippets
                .insert(0, format!("secret-like: {safe}"));
            if let Some(hit) = self.build_hit(
                RiskFlag::SecretExfilHint,
                &format!("{source} text matched secret-like patterns · {safe}"),
                0.85,
                agent.clone(),
                pid,
                trace_id.clone(),
                span_id.clone(),
                EnforcementAction::TerminateProcess,
                ev,
                Some(blob),
            ) {
                hits.push(hit);
            }
        }

        if self.cfg.policy.flag_on_prompt_injection && looks_like_prompt_injection(blob) {
            let mut ev = evidence.clone();
            let safe = redact_secrets(&truncate_snippet(blob, 200));
            ev.text_snippets.insert(0, format!("prompt: {safe}"));
            if let Some(hit) = self.build_hit(
                RiskFlag::PromptInjectionHint,
                &format!("{source} text matched prompt-injection heuristics · {safe}"),
                0.72,
                agent.clone(),
                pid,
                trace_id.clone(),
                span_id.clone(),
                EnforcementAction::RecordOnly,
                ev,
                Some(blob),
            ) {
                hits.push(hit);
            }
        }

        if self.cfg.policy.flag_on_remote_control && looks_like_remote_control(blob) {
            let mut ev = evidence.clone();
            let safe = redact_secrets(&truncate_snippet(blob, 200));
            ev.text_snippets
                .insert(0, format!("remote-control: {safe}"));
            if let Some(hit) = self.build_hit(
                RiskFlag::RemoteControlHint,
                &format!(
                    "{source} text matched remote-control / reverse-shell heuristics · {safe}"
                ),
                0.88,
                agent,
                pid,
                trace_id,
                span_id,
                EnforcementAction::TerminateProcess,
                ev,
                Some(blob),
            ) {
                hits.push(hit);
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
        mut evidence: RiskEvidence,
        dedupe_seed: Option<&str>,
    ) -> Option<PolicyHit> {
        let piece = dedupe_seed
            .map(|s| s.to_string())
            .or_else(|| evidence.text_snippets.first().cloned())
            .or_else(|| evidence.commands.first().cloned())
            .or_else(|| evidence.network_requests.first().cloned())
            .or_else(|| evidence.request_summary.clone())
            .unwrap_or_else(|| reason.to_string());
        let piece_key = format!(
            "{}:{}:{}",
            agent.as_deref().unwrap_or("-"),
            flag.as_str(),
            archimede_core::fingerprint_piece(&piece)
        );
        // Same threat content → never emit again this process (DB also dedupes by stable id).
        if !self.mark_piece_once(&piece_key) {
            return None;
        }
        // Soft rate-limit distinct pieces of the same flag type.
        let rate_key = format!("{}:{}", agent.as_deref().unwrap_or("-"), flag.as_str());
        if !self.allow_fire(&rate_key) {
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

        if evidence.pid.is_none() {
            evidence.pid = pid;
        }
        if evidence.trace_id.is_none() {
            evidence.trace_id = trace_id.clone();
        }
        if evidence.span_id.is_none() {
            evidence.span_id = span_id.clone();
        }
        evidence.risk_score = Some(score);
        // Redact any credential-shaped content before persistence / API return.
        evidence = redact_evidence(evidence);

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
            evidence: evidence.clone(),
        };

        let alert_id = stable_event_id(
            agent.as_deref(),
            flag.as_str(),
            &piece,
            "alert",
        );
        let decision_id = stable_event_id(
            agent.as_deref(),
            flag.as_str(),
            &piece,
            "decision",
        );

        let alert = Event::with_id(
            alert_id,
            "policy",
            EventKind::Alert {
                flag,
                agent: agent.clone(),
                message: reason.to_string(),
                score,
                evidence,
            },
        );
        let decision_event =
            Event::with_id(decision_id, "policy", EventKind::PolicyDecision(decision.clone()));
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

    /// Remember a threat piece for the life of the daemon (cleared only by restart / forget).
    fn mark_piece_once(&self, key: &str) -> bool {
        let mut map = self.seen_pieces.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(key) {
            return false;
        }
        map.insert(key.to_string(), Utc::now());
        // Soft bound memory if enormous.
        if map.len() > 50_000 {
            let cutoff = Utc::now() - chrono::Duration::hours(24);
            map.retain(|_, ts| *ts > cutoff);
        }
        true
    }

    /// Forget in-memory dedupe (e.g. after UI Clear all).
    pub fn forget_seen(&self) {
        if let Ok(mut map) = self.seen_pieces.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.last_fire.lock() {
            map.clear();
        }
    }
}

fn truncate_snippet(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(max).collect::<String>())
    }
}

fn redact_evidence(mut evidence: RiskEvidence) -> RiskEvidence {
    evidence.commands = evidence.commands.into_iter().map(|s| redact_secrets(&s)).collect();
    evidence.text_snippets = evidence
        .text_snippets
        .into_iter()
        .map(|s| redact_secrets(&s))
        .collect();
    evidence.request_summary = evidence
        .request_summary
        .map(|s| redact_secrets(&s));
    evidence.response_summary = evidence
        .response_summary
        .map(|s| redact_secrets(&s));
    evidence.process_path = evidence.process_path.map(|s| redact_secrets(&s));
    evidence
}

fn evidence_from_span(span: &SpanRecord) -> RiskEvidence {
    let mut network_requests = Vec::new();
    if let Some(hosts) = span.attrs.get("egress_hosts").and_then(|v| v.as_array()) {
        for host in hosts.iter().filter_map(|v| v.as_str()).take(8) {
            network_requests.push(host.to_string());
        }
    }
    let mut text_snippets = Vec::new();
    if let Some(input) = &span.input_summary {
        text_snippets.push(format!("req: {input}"));
    }
    if let Some(output) = &span.output_summary {
        text_snippets.push(format!("res: {output}"));
    }
    // Claimed PID is kept for human reporting only; evaluate_span never enforces on it.
    let pid = span
        .attrs
        .get("pid")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let process_path = span
        .attrs
        .get("process_path")
        .or_else(|| span.attrs.get("cmdline"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let process_name = span
        .attrs
        .get("process_name")
        .or_else(|| span.attrs.get("comm"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut commands = Vec::new();
    if let Some(cmd) = span
        .attrs
        .get("command")
        .or_else(|| span.attrs.get("argv"))
        .and_then(|v| v.as_str())
    {
        commands.push(cmd.to_string());
    } else if matches!(span.kind, SpanKind::Tool) {
        commands.push(span.name.clone());
    }

    let mut files = Vec::new();
    for key in ["path", "file", "filepath", "target"] {
        if let Some(p) = span.attrs.get(key).and_then(|v| v.as_str()) {
            if !files.iter().any(|x| x == p) {
                files.push(p.to_string());
            }
        }
    }
    if let Some(arr) = span
        .attrs
        .get("paths")
        .or_else(|| span.attrs.get("files"))
        .and_then(|v| v.as_array())
    {
        for p in arr.iter().filter_map(|v| v.as_str()).take(8) {
            if !files.iter().any(|x| x == p) {
                files.push(p.to_string());
            }
        }
    }

    RiskEvidence {
        pid,
        ppid: None,
        process_name,
        process_path,
        cwd: span
            .attrs
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        commands,
        behavior: Some(format!("span:{}", span.kind.as_str())),
        behavior_confidence: None,
        risk_score: None,
        text_snippets,
        network_requests,
        remotes: Vec::new(),
        binaries: Vec::new(),
        files,
        trace_id: Some(span.trace_id.clone()),
        span_id: Some(span.span_id.clone()),
        request_summary: span.input_summary.clone(),
        response_summary: span.output_summary.clone(),
    }
}

fn preferred_action(flag: RiskFlag) -> EnforcementAction {
    match flag {
        RiskFlag::MassDelete
        | RiskFlag::UnknownBinaryStorm
        | RiskFlag::SecretExfilHint
        | RiskFlag::RemoteControlHint
        | RiskFlag::UnauthorizedTool
        | RiskFlag::ShadowBinary => EnforcementAction::TerminateProcess,
        RiskFlag::HighEgress | RiskFlag::NewRemoteHost | RiskFlag::SuspiciousDns => {
            EnforcementAction::DenyEgress
        }
        _ => EnforcementAction::RecordOnly,
    }
}
