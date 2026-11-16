use anyhow::{anyhow, Context, Result};
use archimede_core::BehaviorLabel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct SystemOneRequest {
    pub model: String,
    pub state: String,
    pub questions: HashMap<String, Question>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Question {
    #[serde(rename = "type")]
    pub qtype: String,
    pub instructions: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
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
        let labels: Vec<String> = BehaviorLabel::all()
            .iter()
            .map(|l| l.as_str().to_string())
            .collect();
        let mut questions = HashMap::new();
        questions.insert(
            "behavior".into(),
            Question {
                qtype: "choice".into(),
                instructions: "Classify the primary agent behavior for this monitoring bucket."
                    .into(),
                choices: Some(labels.clone()),
            },
        );
        questions.insert(
            "risk".into(),
            Question {
                qtype: "score".into(),
                instructions:
                    "Score security risk from 0 (benign collaboration) to 1 (likely harmful)."
                        .into(),
                choices: None,
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

        // Elevate to risky_egress if risk score high and remotes present in state.
        let risk = answer
            .score
            .or_else(|| {
                resp.answers
                    .get("risk")
                    .and_then(|a| a.score.or(a.confidence))
            })
            .unwrap_or(0.0);
        let label = if risk >= 0.75 && state.contains("egress_score") {
            BehaviorLabel::RiskyEgress
        } else {
            label
        };

        Ok(Classification {
            label,
            confidence: conf,
            source: "systemone".into(),
            probabilities,
        })
    }
}
