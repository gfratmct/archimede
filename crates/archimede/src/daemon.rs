use crate::api;
use anyhow::Result;
use archimede_classify::BehaviorClassifier;
use archimede_collect::spawn_all;
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

            if let EventKind::Span(span) = &event.kind {
                for hit in policy_c.evaluate_span(span) {
                    {
                        let s = store_c.lock().await;
                        let _ = s.insert_event(&hit.alert);
                        let _ = s.insert_event(&hit.decision_event);
                    }
                    let _ = bus_c.publish(hit.alert);
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
    api::serve(cfg.clone(), store, bus).await
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
        {
            let s = store.lock().await;
            let _ = s.insert_event(&hit.alert);
            let _ = s.insert_event(&hit.decision_event);
        }
        let _ = bus.publish(hit.alert);
        let _ = bus.publish(hit.decision_event);
    }

    // Classification
    match classifier.classify_bucket(&bucket).await {
        Ok(c) => {
            let ev = Event::new(
                "classify",
                EventKind::Classification {
                    agent: agent.clone(),
                    label: c.label,
                    confidence: c.confidence,
                    source: c.source.clone(),
                },
            );
            {
                let s = store.lock().await;
                let _ = s.insert_event(&ev);
            }
            let _ = bus.publish(ev);

            if c.confidence >= cfg.alerts.risk_score_threshold
                && matches!(c.label, archimede_core::BehaviorLabel::RiskyEgress)
            {
                let ev = Event::new(
                    "classify",
                    EventKind::Alert {
                        flag: archimede_core::RiskFlag::ElevatedRiskScore,
                        agent: Some(agent.clone()),
                        message: format!(
                            "{} classified as risky_egress ({:.2})",
                            agent, c.confidence
                        ),
                        score: c.confidence,
                    },
                );
                {
                    let s = store.lock().await;
                    let _ = s.insert_event(&ev);
                }
                let _ = bus.publish(ev);
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
