use archimede::classify::rule_classify;
use archimede::core::{
    AgentCatalog, Config, Event, EventBus, EventKind, ProcessSnapshot, Store,
};
use archimede::features::{export_buckets_jsonl, BucketAggregator, FeatureBucket};
use archimede::forecast::BaselineForecaster;
use chrono::Utc;
use std::path::PathBuf;

#[test]
fn end_to_end_synthetic_pipeline() {
    let cfg = Config::default();
    let catalog = AgentCatalog::from_config(&cfg.attribution.agents);
    assert!(catalog
        .match_process("cursor", "/opt/cursor/cursor")
        .is_some());

    let store = Store::open_in_memory().unwrap();
    let (bus, rx) = EventBus::unbounded();

    let ev = Event::new(
        "fixture",
        EventKind::ProcessSnapshot(ProcessSnapshot {
            pid: 4242,
            ppid: 1,
            comm: "cursor".into(),
            cmdline: "cursor --agent".into(),
            cwd: Some("/tmp".into()),
            rss_bytes: 123_456,
            cpu_pct: 11.0,
            agent: Some("cursor".into()),
            family: Some("coding_agent".into()),
        }),
    );
    bus.publish(ev.clone()).unwrap();
    store.insert_event(&ev).unwrap();

    let mut agg = BucketAggregator::new(30);
    let _ = agg.ingest(&ev);
    for i in 0..12 {
        let mut e = Event::new(
            "fixture",
            EventKind::Exec {
                pid: 5000 + i,
                ppid: 4242,
                comm: "bash".into(),
                argv_summary: "/bin/bash -lc rg".into(),
            },
        );
        e.agent = Some("cursor".into());
        let _ = agg.ingest(&e);
        store.insert_event(&e).unwrap();
    }

    let buckets = agg.flush();
    assert!(!buckets.is_empty());
    let bucket = &buckets[0];
    let classification = rule_classify(bucket);
    assert_eq!(
        classification.label,
        archimede::core::BehaviorLabel::ShellTools
    );

    let hist: Vec<f64> = (1..40).map(|x| x as f64).collect();
    let forecast = BaselineForecaster::new(8).forecast("exec_count", &hist);
    assert_eq!(forecast.predicted.len(), 8);

    let received = rx.try_recv().unwrap();
    assert!(matches!(received.kind, EventKind::ProcessSnapshot(_)));

    let stats = store.stats().unwrap();
    assert!(stats.total_events >= 13);

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test_buckets.jsonl");
    export_buckets_jsonl(&out, &buckets).unwrap();
    assert!(out.exists());
}

#[test]
fn loads_repo_yaml_config() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs/archimede.yaml");
    let cfg = Config::load(&path).unwrap();
    assert_eq!(cfg.daemon.bind, "127.0.0.1:7432");
    assert!(!cfg.attribution.agents.is_empty());
}

#[test]
fn feature_bucket_state_text() {
    let mut b = FeatureBucket::new(Utc::now(), "cursor");
    b.exec_count = 3;
    b.coding_hints = 2;
    let state = b.to_state_text();
    assert!(state.contains("agent=cursor"));
    assert!(state.contains("execs=3"));
}
