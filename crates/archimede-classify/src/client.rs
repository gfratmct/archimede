use anyhow::{anyhow, Context, Result};
use archimede_core::BehaviorLabel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Ordered risk rubric (lowest → highest). Score answers are expected level indices.
const RISK_LEVELS: &[&str] = &["benign", "low", "elevated", "high", "harmful"];

fn behavior_criteria() -> HashMap<String, String> {
    BehaviorLabel::all()
        .iter()
        .map(|l| {
            let desc = match l {
                BehaviorLabel::Idle => "no meaningful agent activity",
                BehaviorLabel::Planning => "reasoning or planning next steps",
                BehaviorLabel::Coding => "editing or generating source code",
                BehaviorLabel::Testing => "running tests or verifying behavior",
                BehaviorLabel::ShellTools => "shell commands and local tooling",
                BehaviorLabel::Browsing => "web, docs, or remote content access",
                BehaviorLabel::LlmWait => "waiting on model or API responses",
                BehaviorLabel::RiskyEgress => {
                    "suspicious outbound traffic or destructive activity"
                }
            };
            (l.as_str().to_string(), desc.to_string())
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemOneRequest {
    pub model: String,
    pub state: String,
    pub questions: HashMap<String, Question>,
}

/// System One / llama.cpp `/v1/systemone` question.
/// `choice` criteria must be a non-empty object; `score` criteria an array of 2–10 levels.
#[derive(Debug, Clone, Serialize)]
pub struct Question {
    #[serde(rename = "type")]
    pub qtype: String,
    pub instructions: String,
    pub criteria: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemOneResponse {
    #[serde(default)]
    pub answers: HashMap<String, Answer>,
    // Some servers nest differently; keep raw flexibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Answer {
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub choice: Option<String>,
    #[serde(default)]
    pub probabilities: Option<HashMap<String, f32>>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub score: Option<f32>,
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub label: BehaviorLabel,
    pub confidence: f32,
    pub source: String,
    pub probabilities: HashMap<String, f32>,
    /// Normalized System-One risk score in `[0, 1]` (expected rubric level / max).
    pub risk_score: f32,
}

pub struct SystemOneClient {
    http: reqwest::Client,
    endpoint: String,
    model: String,
}

impl SystemOneClient {
    pub fn new(endpoint: &str, model: &str, timeout_ms: u64) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .expect("reqwest client");
        Self {
            http,
            endpoint: endpoint.to_string(),
            model: model.to_string(),
        }
    }

    pub async fn decide(&self, req: &SystemOneRequest) -> Result<SystemOneResponse> {
        let resp = self
            .http
            .post(&self.endpoint)
            .json(req)
            .send()
            .await
            .context("system-one HTTP request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("system-one status {status}: {body}"));
        }
        resp.json::<SystemOneResponse>()
            .await
            .context("decode system-one response")
    }

    pub async fn classify_behavior(&self, state: &str) -> Result<Classification> {
        let mut questions = HashMap::new();
        questions.insert(
            "behavior".into(),
            Question {
                qtype: "choice".into(),
                instructions: "Classify the primary agent behavior for this monitoring bucket."
                    .into(),
                criteria: serde_json::to_value(behavior_criteria())
                    .expect("behavior criteria serializes"),
            },
        );
        questions.insert(
            "risk".into(),
            Question {
                qtype: "score".into(),
                instructions:
                    "Score security risk from benign collaboration to likely harmful.".into(),
                criteria: serde_json::to_value(RISK_LEVELS).expect("risk criteria serializes"),
            },
        );

        let req = SystemOneRequest {
            model: self.model.clone(),
            state: state.to_string(),
            questions,
        };
        let resp = self.decide(&req).await?;
        let answer = resp
            .answers
            .get("behavior")
            .ok_or_else(|| anyhow!("missing behavior answer"))?;

        let (label_str, conf) = if let Some(choice) = &answer.choice {
            let conf = answer
                .probabilities
                .as_ref()
                .and_then(|p| p.get(choice).copied())
                .or(answer.confidence)
                .unwrap_or(0.6);
            (choice.clone(), conf)
        } else if let Some(serde_json::Value::String(s)) = &answer.value {
            (s.clone(), answer.confidence.unwrap_or(0.55))
        } else if let Some(probs) = &answer.probabilities {
            probs
                .iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, v)| (k.clone(), *v))
                .ok_or_else(|| anyhow!("empty probabilities"))?
        } else {
            return Err(anyhow!("unrecognized system-one answer shape"));
        };

        let label = BehaviorLabel::parse(&label_str).unwrap_or(BehaviorLabel::Idle);
        let mut probabilities = answer.probabilities.clone().unwrap_or_default();
        if probabilities.is_empty() {
            probabilities.insert(label.as_str().to_string(), conf);
        }

        // Julia returns expected level index in [0, n_levels-1]; normalize to [0, 1].
        let risk_raw = resp
            .answers
            .get("risk")
            .and_then(|a| a.score.or(a.confidence))
            .unwrap_or(0.0);
        let denom = (RISK_LEVELS.len().saturating_sub(1).max(1)) as f32;
        let risk_score = (risk_raw / denom).clamp(0.0, 1.0);
        // Only force risky_egress when the state shows meaningful egress, not merely
        // because the template string always contains the key "egress_score".
        let egress_high = state
            .split(';')
            .find_map(|part| {
                let p = part.trim();
                p.strip_prefix("egress_score=")
                    .and_then(|v| v.parse::<f64>().ok())
            })
            .map(|v| v >= 1.0)
            .unwrap_or(false);
        let label = if risk_score >= 0.75 && egress_high {
            BehaviorLabel::RiskyEgress
        } else {
            label
        };

        Ok(Classification {
            label,
            confidence: conf,
            source: "systemone".into(),
            probabilities,
            risk_score,
        })
    }
}
