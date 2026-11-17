use crate::api;
use anyhow::Result;
use archimede_classify::BehaviorClassifier;
use archimede_collect::{file_ops_from_span, spawn_all};
use archimede_core::{AgentCatalog, Config, Event, EventBus, EventKind, Store};
use archimede_features::BucketAggregator;
use archimede_forecast::ForecastEngine;
use archimede_policy::PolicyEngine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn run(cfg: Arc<Config>) -> Result<()> {
    let data_dir = cfg.expand_data_dir();
    std::fs::create_dir_all(&data_dir)?;
    let db_path = data_dir.join("archimede.sqlite");
    let store = Arc::new(Mutex::new(Store::open(&db_path)?));
    tracing::info!(path = %db_path.display(), "opened store");

    let catalog = Arc::new(AgentCatalog::from_config(&cfg.attribution.agents));
    let (bus, rx) = EventBus::unbounded();
    let policy = Arc::new(PolicyEngine::new(cfg.clone()));

    let _collectors = spawn_all(cfg.clone(), catalog, bus.clone());

    let classifier = Arc::new(BehaviorClassifier::from_config(&cfg));
    let forecaster = Arc::new(ForecastEngine::from_config(&cfg));
    let aggregator = Arc::new(Mutex::new(BucketAggregator::new(cfg.daemon.bucket_secs)));
    let history: Arc<Mutex<HashMap<String, Vec<archimede_features::FeatureBucket>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Persist + aggregate consumer
    let store_c = store.clone();
    let agg_c = aggregator.clone();
    let cfg_c = cfg.clone();
    let hist_c = history.clone();
    let classifier_c = classifier.clone();
    let forecaster_c = forecaster.clone();
    let bus_c = bus.clone();
    let policy_c = policy.clone();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv_async().await {
            {
                let s = store_c.lock().await;
                if let Err(e) = s.insert_event(&event) {
                    tracing::warn!(error = %e, "store insert");
                }
            }

            // Derive create/edit/delete file logs from harness tool spans.
            if let EventKind::Span(span) = &event.kind {
                for op in file_ops_from_span(span) {
                    let file_ev = Event::new("span_files", EventKind::File(op));
                    {
                        let s = store_c.lock().await;
                        let _ = s.insert_event(&file_ev);
                    }
                    {
                        let mut agg = agg_c.lock().await;
                        let _ = agg.ingest(&file_ev);
                    }
                }
            }

            let policy_hits = match &event.kind {
                EventKind::Span(span) => policy_c.evaluate_span(span),
                EventKind::Session(session) => policy_c.evaluate_session(session),
                EventKind::Exec {
                    argv_summary,
                    comm,
                    pid,
                    ..
                } => {
                    // Fast path for reverse-shell style argv before bucket flush.
                    let blob = format!("{comm} {argv_summary}");
                    policy_c.evaluate_exec_argv(&blob, event.agent.clone(), Some(*pid))
                }
                _ => Vec::new(),
            };
            for hit in policy_hits {
                let (new_alert, new_decision) = {
                    let s = store_c.lock().await;
                    let a = s.insert_event(&hit.alert).unwrap_or(false);
                    let d = s.insert_event(&hit.decision_event).unwrap_or(false);
                    (a, d)
                };
                if new_alert {
                    let _ = bus_c.publish(hit.alert);
                }
                if new_decision {
                    let _ = bus_c.publish(hit.decision_event);
                }
            }

            let flushed = {
                let mut agg = agg_c.lock().await;
                agg.ingest(&event)
            };

            for bucket in flushed {
                process_bucket(
                    &cfg_c,
                    &store_c,
                    &classifier_c,
                    &forecaster_c,
                    &hist_c,
                    &bus_c,
                    &policy_c,
                    bucket,
                )
                .await;
            }
        }
    });

    // Periodic flush of open buckets
    let agg_f = aggregator.clone();
    let store_f = store.clone();
    let cfg_f = cfg.clone();
    let hist_f = history.clone();
    let classifier_f = classifier.clone();
    let forecaster_f = forecaster.clone();
    let bus_f = bus.clone();
    let policy_f = policy.clone();
    tokio::spawn(async move {
        let period = std::time::Duration::from_secs(cfg_f.daemon.bucket_secs.max(5));
        loop {
            tokio::time::sleep(period).await;
            let flushed = {
                let mut agg = agg_f.lock().await;
                agg.flush()
            };
            for bucket in flushed {
                process_bucket(
                    &cfg_f,
                    &store_f,
                    &classifier_f,
                    &forecaster_f,
                    &hist_f,
                    &bus_f,
                    &policy_f,
                    bucket,
                )
                .await;
            }
        }
    });

    tracing::info!(
        bind = %cfg.daemon.bind,
        enforcement = cfg.enforcement.enabled,
        "starting API"
    );
    api::serve(cfg.clone(), store, bus, policy).await
}

#[allow(clippy::too_many_arguments)]
async fn process_bucket(
    cfg: &Config,
    store: &Arc<Mutex<Store>>,
    classifier: &BehaviorClassifier,
    forecaster: &ForecastEngine,
    history: &Arc<Mutex<HashMap<String, Vec<archimede_features::FeatureBucket>>>>,
    bus: &EventBus,
    policy: &PolicyEngine,
    bucket: archimede_features::FeatureBucket,
) {
    let agent = bucket.agent.clone();
    let payload = bucket.to_json();

    {
        let s = store.lock().await;
        let _ = s.insert_bucket(bucket.ts, &agent, &payload);
        for (metric, value) in bucket.metric_map() {
            let _ = s.insert_metric(bucket.ts, &agent, &metric, value);
        }
    }

    // Policy + legacy risk rules (policy covers bucket risks + new flags)
    for hit in policy.evaluate_bucket(&bucket) {
        let (new_alert, new_decision) = {
            let s = store.lock().await;
            let a = s.insert_event(&hit.alert).unwrap_or(false);
            let d = s.insert_event(&hit.decision_event).unwrap_or(false);
            (a, d)
        };
        if new_alert {
            let _ = bus.publish(hit.alert);
        }
        if new_decision {
            let _ = bus.publish(hit.decision_event);
        }
    }

    // Classification (still recorded for inactive agents; alerts only when active + concrete)
    match classifier.classify_bucket(&bucket).await {
        Ok(c) => {
            let ev = Event::new(
                "classify",
                EventKind::Classification {
                    agent: agent.clone(),
                    label: c.label,
                    confidence: c.confidence,
                    source: c.source.clone(),
                    risk_score: Some(c.risk_score),
                    probabilities: c.probabilities.clone(),
                },
            );
            {
                let s = store.lock().await;
                let _ = s.insert_event(&ev);
            }
            let _ = bus.publish(ev);

            let top = {
                let mut pairs: Vec<_> = c.probabilities.iter().collect();
                pairs.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
                pairs
                    .into_iter()
                    .take(3)
                    .map(|(k, v)| format!("{k}={:.0}%", v * 100.0))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            if let Some(hit) = policy.evaluate_classification_risk(
                &bucket,
                c.label.as_str(),
                c.confidence,
                c.risk_score,
                &top,
            ) {
                let (new_alert, new_decision) = {
                    let s = store.lock().await;
                    let a = s.insert_event(&hit.alert).unwrap_or(false);
                    let d = s.insert_event(&hit.decision_event).unwrap_or(false);
                    (a, d)
                };
                if new_alert {
                    let _ = bus.publish(hit.alert);
                }
                if new_decision {
                    let _ = bus.publish(hit.decision_event);
                }
            }
        }
        Err(e) => tracing::debug!(error = %e, "classification skipped"),
    }

    // History + forecast
    let series = {
        let mut h = history.lock().await;
        let entry = h.entry(agent.clone()).or_default();
        entry.push(bucket.clone());
        if entry.len() > cfg.forecast.context_len {
            let overflow = entry.len() - cfg.forecast.context_len;
            entry.drain(0..overflow);
        }
        entry.clone()
    };

    if series.len() >= 8 {
        let metrics = [
            "exec_count",
            "socket_count",
            "egress_proxy_score",
            "cpu_pct_max",
            "span_count",
        ];
        if let Ok(forecasts) = forecaster.forecast_buckets(&series, &metrics).await {
            for f in forecasts {
                let ev = Event::new(
                    "forecast",
                    EventKind::Forecast {
                        metric: f.metric,
                        horizon_steps: f.predicted.len(),
                        predicted: f.predicted,
                        lower: f.lower,
                        upper: f.upper,
                    },
                );
                {
                    let s = store.lock().await;
                    let _ = s.insert_event(&ev);
                }
                let _ = bus.publish(ev);
            }
        }
    }
}
