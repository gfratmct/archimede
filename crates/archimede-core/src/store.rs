use crate::event::{BehaviorLabel, Event, EventKind, RiskFlag};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSummary {
    pub total_events: i64,
    pub agents_seen: Vec<String>,
    pub alerts: i64,
    pub last_classification: Option<ClassificationRow>,
    pub buckets: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRow {
    pub ts: DateTime<Utc>,
    pub agent: String,
    pub label: String,
    pub confidence: f32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRow {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub agent: Option<String>,
    pub flag: String,
    pub message: String,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub ts: DateTime<Utc>,
    pub agent: String,
    pub metric: String,
    pub value: f64,
}

/// SQLite WAL store for events, classifications, alerts, and metric series.
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path.as_ref())
            .with_context(|| format!("opening sqlite {}", path.as_ref().display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;",
        )?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                source TEXT NOT NULL,
                agent TEXT,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent);

            CREATE TABLE IF NOT EXISTS classifications (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                agent TEXT NOT NULL,
                label TEXT NOT NULL,
                confidence REAL NOT NULL,
                source TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_class_ts ON classifications(ts);

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                agent TEXT,
                flag TEXT NOT NULL,
                message TEXT NOT NULL,
                score REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

            CREATE TABLE IF NOT EXISTS metrics (
                ts TEXT NOT NULL,
                agent TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                PRIMARY KEY (ts, agent, metric)
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_agent_metric ON metrics(agent, metric, ts);

            CREATE TABLE IF NOT EXISTS buckets (
                ts TEXT NOT NULL,
                agent TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (ts, agent)
            );
            ",
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &Event) -> Result<()> {
        let kind = kind_name(&event.kind);
        let payload = serde_json::to_string(event)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO events (id, ts, source, agent, kind, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.id.to_string(),
                event.ts.to_rfc3339(),
                event.source,
                event.agent,
                kind,
                payload
            ],
        )?;

        match &event.kind {
            EventKind::Classification {
                agent,
                label,
                confidence,
                source,
            } => {
                self.conn.execute(
                    "INSERT OR REPLACE INTO classifications
                     (id, ts, agent, label, confidence, source)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        event.id.to_string(),
                        event.ts.to_rfc3339(),
                        agent,
                        label.as_str(),
                        confidence,
                        source
                    ],
                )?;
            }
            EventKind::Alert {
                flag,
                agent,
                message,
                score,
            } => {
                self.conn.execute(
                    "INSERT OR REPLACE INTO alerts (id, ts, agent, flag, message, score)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        event.id.to_string(),
                        event.ts.to_rfc3339(),
                        agent,
                        flag.as_str(),
                        message,
                        score
                    ],
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn insert_metric(
        &self,
        ts: DateTime<Utc>,
        agent: &str,
        metric: &str,
        value: f64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metrics (ts, agent, metric, value)
             VALUES (?1, ?2, ?3, ?4)",
            params![ts.to_rfc3339(), agent, metric, value],
        )?;
        Ok(())
    }

    pub fn insert_bucket(
        &self,
        ts: DateTime<Utc>,
        agent: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO buckets (ts, agent, payload) VALUES (?1, ?2, ?3)",
            params![ts.to_rfc3339(), agent, payload.to_string()],
        )?;
        Ok(())
    }

    pub fn recent_events(&self, limit: usize, agent: Option<&str>) -> Result<Vec<Event>> {
        let mut out = Vec::new();
        if let Some(agent) = agent {
            let mut stmt = self.conn.prepare(
                "SELECT payload FROM events WHERE agent = ?1 ORDER BY ts DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![agent, limit as i64], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })?;
            for r in rows {
                out.push(serde_json::from_str(&r?)?);
            }
        } else {
            let mut stmt = self
                .conn
                .prepare("SELECT payload FROM events ORDER BY ts DESC LIMIT ?1")?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })?;
            for r in rows {
                out.push(serde_json::from_str(&r?)?);
            }
        }
        Ok(out)
    }

    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<AlertRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, agent, flag, message, score FROM alerts ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts: String = row.get(1)?;
            Ok(AlertRow {
                id: row.get(0)?,
                ts: DateTime::parse_from_rfc3339(&ts)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                agent: row.get(2)?,
                flag: row.get(3)?,
                message: row.get(4)?,
                score: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn metric_series(
        &self,
        agent: &str,
        metric: &str,
        limit: usize,
    ) -> Result<Vec<MetricPoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, value FROM metrics WHERE agent = ?1 AND metric = ?2
             ORDER BY ts DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![agent, metric, limit as i64], |row| {
            let ts: String = row.get(0)?;
            Ok(MetricPoint {
                ts: DateTime::parse_from_rfc3339(&ts)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                agent: agent.to_string(),
                metric: metric.to_string(),
                value: row.get(1)?,
            })
        })?;
        let mut out: Vec<_> = rows.filter_map(|r| r.ok()).collect();
        out.reverse();
        Ok(out)
    }

    pub fn stats(&self) -> Result<StatsSummary> {
        let total_events: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        let alerts: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))?;
        let buckets: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM buckets", [], |r| r.get(0))?;

        let mut agents = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT agent FROM events WHERE agent IS NOT NULL ORDER BY agent",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for r in rows {
            agents.push(r?);
        }

        let last_classification = self
            .conn
            .query_row(
                "SELECT ts, agent, label, confidence, source FROM classifications
                 ORDER BY ts DESC LIMIT 1",
                [],
                |row| {
                    let ts: String = row.get(0)?;
                    Ok(ClassificationRow {
                        ts: DateTime::parse_from_rfc3339(&ts)
                            .map(|d| d.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        agent: row.get(1)?,
                        label: row.get(2)?,
                        confidence: row.get(3)?,
                        source: row.get(4)?,
                    })
                },
            )
            .optional()?;

        Ok(StatsSummary {
            total_events,
            agents_seen: agents,
            alerts,
            last_classification,
            buckets,
        })
    }

    pub fn record_classification(
        &self,
        agent: &str,
        label: BehaviorLabel,
        confidence: f32,
        source: &str,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let ts = Utc::now();
        self.conn.execute(
            "INSERT INTO classifications (id, ts, agent, label, confidence, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                ts.to_rfc3339(),
                agent,
                label.as_str(),
                confidence,
                source
            ],
        )?;
        Ok(id)
    }

    pub fn record_alert(
        &self,
        flag: RiskFlag,
        agent: Option<&str>,
        message: &str,
        score: f32,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let ts = Utc::now();
        self.conn.execute(
            "INSERT INTO alerts (id, ts, agent, flag, message, score)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                ts.to_rfc3339(),
                agent,
                flag.as_str(),
                message,
                score
            ],
        )?;
        Ok(id)
    }
}

fn kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::ProcessSnapshot(_) => "process_snapshot",
        EventKind::Exec { .. } => "exec",
        EventKind::Connect { .. } => "connect",
        EventKind::Dns { .. } => "dns",
        EventKind::File(_) => "file",
        EventKind::NetworkMeta(_) => "network_meta",
        EventKind::Session(_) => "session",
        EventKind::Classification { .. } => "classification",
        EventKind::Forecast { .. } => "forecast",
        EventKind::Alert { .. } => "alert",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind, ProcessSnapshot};

    #[test]
    fn insert_and_stats() {
        let store = Store::open_in_memory().unwrap();
        let ev = Event::new(
            "test",
            EventKind::ProcessSnapshot(ProcessSnapshot {
                pid: 1,
                ppid: 0,
                comm: "cursor".into(),
                cmdline: "cursor".into(),
                cwd: None,
                rss_bytes: 1000,
                cpu_pct: 1.0,
                agent: Some("cursor".into()),
                family: Some("coding_agent".into()),
            }),
        );
        store.insert_event(&ev).unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.agents_seen, vec!["cursor".to_string()]);
    }
}
