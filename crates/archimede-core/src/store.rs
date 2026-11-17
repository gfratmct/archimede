use crate::event::{
    BehaviorLabel, Event, EventKind, PolicyDecision, RiskEvidence, RiskFlag, SpanRecord,
    TraceRecord,
};
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
    pub traces: i64,
    pub spans: i64,
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
    #[serde(default)]
    pub evidence: RiskEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub ts: DateTime<Utc>,
    pub agent: String,
    pub metric: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagRow {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub agent: Option<String>,
    pub flag: String,
    pub message: String,
    pub score: f32,
    pub trace_id: Option<String>,
    #[serde(default)]
    pub evidence: RiskEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementRow {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub agent: Option<String>,
    pub flag: String,
    pub action: String,
    pub reason: String,
    pub pid: Option<i32>,
    pub trace_id: Option<String>,
    pub enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTree {
    pub trace: TraceRecord,
    pub spans: Vec<SpanRecord>,
}

/// SQLite WAL store for events, classifications, alerts, traces, and metric series.
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
        store.migrate_columns()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        store.migrate_columns()?;
        Ok(store)
    }

    fn migrate_columns(&self) -> Result<()> {
        // Additive columns for existing DBs; ignore "duplicate column" errors.
        let _ = self
            .conn
            .execute("ALTER TABLE alerts ADD COLUMN evidence TEXT", []);
        let _ = self
            .conn
            .execute("ALTER TABLE flags ADD COLUMN evidence TEXT", []);
        Ok(())
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
                score REAL NOT NULL,
                evidence TEXT
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

            CREATE TABLE IF NOT EXISTS traces (
                trace_id TEXT PRIMARY KEY,
                name TEXT,
                agent TEXT,
                harness TEXT,
                user_id TEXT,
                session_id TEXT,
                metadata TEXT NOT NULL,
                start_ts TEXT NOT NULL,
                end_ts TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_traces_agent ON traces(agent);
            CREATE INDEX IF NOT EXISTS idx_traces_start ON traces(start_ts);

            CREATE TABLE IF NOT EXISTS spans (
                span_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                parent_span_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                agent TEXT,
                harness TEXT,
                model TEXT,
                input_summary TEXT,
                output_summary TEXT,
                attrs TEXT NOT NULL,
                start_ts TEXT NOT NULL,
                end_ts TEXT,
                status TEXT,
                token_usage TEXT,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id);
            CREATE INDEX IF NOT EXISTS idx_spans_agent ON spans(agent);
            CREATE INDEX IF NOT EXISTS idx_spans_start ON spans(start_ts);

            CREATE TABLE IF NOT EXISTS flags (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                agent TEXT,
                flag TEXT NOT NULL,
                message TEXT NOT NULL,
                score REAL NOT NULL,
                trace_id TEXT,
                evidence TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_flags_ts ON flags(ts);
            CREATE INDEX IF NOT EXISTS idx_flags_flag ON flags(flag);
            CREATE INDEX IF NOT EXISTS idx_flags_trace ON flags(trace_id);

            CREATE TABLE IF NOT EXISTS enforcement_actions (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                agent TEXT,
                flag TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                pid INTEGER,
                trace_id TEXT,
                enforced INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_enforce_ts ON enforcement_actions(ts);
            ",
        )?;
        Ok(())
    }

    /// Insert an event. Returns `false` when an alert/flag/decision with the same
    /// id already exists (content dedupe) so callers can skip re-publishing.
    pub fn insert_event(&self, event: &Event) -> Result<bool> {
        let kind = kind_name(&event.kind);
        let payload = serde_json::to_string(event)?;
        let mut novel = false;

        let n = self.conn.execute(
            "INSERT OR IGNORE INTO events (id, ts, source, agent, kind, payload)
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
        novel |= n > 0;

        match &event.kind {
            EventKind::Classification {
                agent,
                label,
                confidence,
                source,
                ..
            } => {
                let n = self.conn.execute(
                    "INSERT OR IGNORE INTO classifications
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
                novel |= n > 0;
            }
            EventKind::Alert {
                flag,
                agent,
                message,
                score,
                evidence,
            } => {
                let evidence_json = serde_json::to_string(evidence).unwrap_or_else(|_| "{}".into());
                let a = self.conn.execute(
                    "INSERT OR IGNORE INTO alerts (id, ts, agent, flag, message, score, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        event.id.to_string(),
                        event.ts.to_rfc3339(),
                        agent,
                        flag.as_str(),
                        message,
                        score,
                        evidence_json.clone()
                    ],
                )?;
                let f = self.conn.execute(
                    "INSERT OR IGNORE INTO flags (id, ts, agent, flag, message, score, trace_id, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        event.id.to_string(),
                        event.ts.to_rfc3339(),
                        agent,
                        flag.as_str(),
                        message,
                        score,
                        evidence.trace_id,
                        evidence_json
                    ],
                )?;
                novel |= a > 0 || f > 0;
            }
            EventKind::Span(span) => {
                self.upsert_span(span)?;
                novel = true;
            }
            EventKind::PolicyDecision(decision) => {
                let n = self.insert_policy_decision(event.id, event.ts, decision)?;
                novel |= n;
            }
            _ => {
                novel |= n > 0;
            }
        }
        Ok(novel)
    }

    pub fn upsert_trace(&self, trace: &TraceRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO traces (trace_id, name, agent, harness, user_id, session_id, metadata, start_ts, end_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(trace_id) DO UPDATE SET
               name=COALESCE(excluded.name, traces.name),
               agent=COALESCE(excluded.agent, traces.agent),
               harness=COALESCE(excluded.harness, traces.harness),
               user_id=COALESCE(excluded.user_id, traces.user_id),
               session_id=COALESCE(excluded.session_id, traces.session_id),
               metadata=excluded.metadata,
               end_ts=COALESCE(excluded.end_ts, traces.end_ts)",
            params![
                trace.trace_id,
                trace.name,
                trace.agent,
                trace.harness,
                trace.user_id,
                trace.session_id,
                trace.metadata.to_string(),
                trace.start_ts.to_rfc3339(),
                trace.end_ts.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub fn upsert_span(&self, span: &SpanRecord) -> Result<()> {
        let token_usage = span
            .token_usage
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let payload = serde_json::to_string(span)?;
        self.conn.execute(
            "INSERT INTO spans (
                span_id, trace_id, parent_span_id, name, kind, agent, harness, model,
                input_summary, output_summary, attrs, start_ts, end_ts, status, token_usage, payload
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
             ON CONFLICT(span_id) DO UPDATE SET
               parent_span_id=excluded.parent_span_id,
               name=excluded.name,
               kind=excluded.kind,
               agent=excluded.agent,
               harness=excluded.harness,
               model=excluded.model,
               input_summary=excluded.input_summary,
               output_summary=excluded.output_summary,
               attrs=excluded.attrs,
               end_ts=excluded.end_ts,
               status=excluded.status,
               token_usage=excluded.token_usage,
               payload=excluded.payload",
            params![
                span.span_id,
                span.trace_id,
                span.parent_span_id,
                span.name,
                span.kind.as_str(),
                span.agent,
                span.harness,
                span.model,
                span.input_summary,
                span.output_summary,
                span.attrs.to_string(),
                span.start_ts.to_rfc3339(),
                span.end_ts.map(|t| t.to_rfc3339()),
                span.status,
                token_usage,
                payload,
            ],
        )?;
        // Ensure parent trace row exists.
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT trace_id FROM traces WHERE trace_id = ?1",
                params![span.trace_id],
                |r| r.get(0),
            )
            .optional()?;
        if existing.is_none() {
            self.upsert_trace(&TraceRecord {
                trace_id: span.trace_id.clone(),
                name: Some(span.name.clone()),
                agent: span.agent.clone(),
                harness: span.harness.clone(),
                user_id: None,
                session_id: None,
                metadata: serde_json::json!({}),
                start_ts: span.start_ts,
                end_ts: span.end_ts,
            })?;
        }
        Ok(())
    }

    fn insert_policy_decision(
        &self,
        id: Uuid,
        ts: DateTime<Utc>,
        decision: &PolicyDecision,
    ) -> Result<bool> {
        // Flags come only from Alert events — avoid a second flag row per hit.
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO enforcement_actions
             (id, ts, agent, flag, action, reason, pid, trace_id, enforced)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id.to_string(),
                ts.to_rfc3339(),
                decision.agent,
                decision.flag.as_str(),
                decision.action.as_str(),
                decision.reason,
                decision.pid,
                decision.trace_id,
                decision.enforced as i32,
            ],
        )?;
        Ok(n > 0)
    }

    pub fn get_trace(&self, trace_id: &str) -> Result<Option<TraceTree>> {
        let trace = self
            .conn
            .query_row(
                "SELECT trace_id, name, agent, harness, user_id, session_id, metadata, start_ts, end_ts
                 FROM traces WHERE trace_id = ?1",
                params![trace_id],
                |row| {
                    let metadata: String = row.get(6)?;
                    let start_ts: String = row.get(7)?;
                    let end_ts: Option<String> = row.get(8)?;
                    Ok(TraceRecord {
                        trace_id: row.get(0)?,
                        name: row.get(1)?,
                        agent: row.get(2)?,
                        harness: row.get(3)?,
                        user_id: row.get(4)?,
                        session_id: row.get(5)?,
                        metadata: serde_json::from_str(&metadata).unwrap_or_default(),
                        start_ts: parse_ts(&start_ts),
                        end_ts: end_ts.as_deref().map(parse_ts),
                    })
                },
            )
            .optional()?;
        let Some(trace) = trace else {
            return Ok(None);
        };
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM spans WHERE trace_id = ?1 ORDER BY start_ts ASC")?;
        let rows = stmt.query_map(params![trace_id], |row| {
            let payload: String = row.get(0)?;
            Ok(payload)
        })?;
        let mut spans = Vec::new();
        for r in rows {
            spans.push(serde_json::from_str(&r?)?);
        }
        Ok(Some(TraceTree { trace, spans }))
    }

    pub fn recent_traces(&self, limit: usize, agent: Option<&str>) -> Result<Vec<TraceRecord>> {
        let mut out = Vec::new();
        if let Some(agent) = agent {
            let mut stmt = self.conn.prepare(
                "SELECT trace_id, name, agent, harness, user_id, session_id, metadata, start_ts, end_ts
                 FROM traces WHERE agent = ?1 ORDER BY start_ts DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![agent, limit as i64], |row| map_trace_row(row))?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT trace_id, name, agent, harness, user_id, session_id, metadata, start_ts, end_ts
                 FROM traces ORDER BY start_ts DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| map_trace_row(row))?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    pub fn recent_flags(
        &self,
        limit: usize,
        agent: Option<&str>,
        trace_id: Option<&str>,
    ) -> Result<Vec<FlagRow>> {
        let mut out = Vec::new();
        match (agent, trace_id) {
            (Some(agent), Some(trace_id)) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, ts, agent, flag, message, score, trace_id, evidence FROM flags
                     WHERE agent = ?1 AND trace_id = ?2 ORDER BY ts DESC LIMIT ?3",
                )?;
                let rows =
                    stmt.query_map(params![agent, trace_id, limit as i64], |row| map_flag_row(row))?;
                for r in rows {
                    out.push(r?);
                }
            }
            (Some(agent), None) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, ts, agent, flag, message, score, trace_id, evidence FROM flags
                     WHERE agent = ?1 ORDER BY ts DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![agent, limit as i64], |row| map_flag_row(row))?;
                for r in rows {
                    out.push(r?);
                }
            }
            (None, Some(trace_id)) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, ts, agent, flag, message, score, trace_id, evidence FROM flags
                     WHERE trace_id = ?1 ORDER BY ts DESC LIMIT ?2",
                )?;
                let rows =
                    stmt.query_map(params![trace_id, limit as i64], |row| map_flag_row(row))?;
                for r in rows {
                    out.push(r?);
                }
            }
            (None, None) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, ts, agent, flag, message, score, trace_id, evidence FROM flags
                     ORDER BY ts DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map(params![limit as i64], |row| map_flag_row(row))?;
                for r in rows {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    pub fn recent_enforcement(&self, limit: usize) -> Result<Vec<EnforcementRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, agent, flag, action, reason, pid, trace_id, enforced
             FROM enforcement_actions ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts: String = row.get(1)?;
            let enforced: i32 = row.get(8)?;
            Ok(EnforcementRow {
                id: row.get(0)?,
                ts: parse_ts(&ts),
                agent: row.get(2)?,
                flag: row.get(3)?,
                action: row.get(4)?,
                reason: row.get(5)?,
                pid: row.get(6)?,
                trace_id: row.get(7)?,
                enforced: enforced != 0,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
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

    /// Wipe alerts and security flags (UI "Clear all").
    pub fn clear_alerts_and_flags(&self) -> Result<(usize, usize)> {
        let alerts = self.conn.execute("DELETE FROM alerts", [])?;
        let flags = self.conn.execute("DELETE FROM flags", [])?;
        let _ = self
            .conn
            .execute("DELETE FROM events WHERE kind IN ('alert', 'policy_decision')", [])?;
        let _ = self.conn.execute("DELETE FROM enforcement_actions", [])?;
        Ok((alerts, flags))
    }

    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<AlertRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, agent, flag, message, score, evidence FROM alerts ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts: String = row.get(1)?;
            let evidence_raw: Option<String> = row.get(6)?;
            Ok(AlertRow {
                id: row.get(0)?,
                ts: parse_ts(&ts),
                agent: row.get(2)?,
                flag: row.get(3)?,
                message: row.get(4)?,
                score: row.get(5)?,
                evidence: parse_evidence(evidence_raw),
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
                ts: parse_ts(&ts),
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
        let traces: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM traces", [], |r| r.get(0))?;
        let spans: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM spans", [], |r| r.get(0))?;

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
                        ts: parse_ts(&ts),
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
            traces,
            spans,
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
            "INSERT INTO alerts (id, ts, agent, flag, message, score, evidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id.to_string(),
                ts.to_rfc3339(),
                agent,
                flag.as_str(),
                message,
                score,
                "{}"
            ],
        )?;
        self.conn.execute(
            "INSERT INTO flags (id, ts, agent, flag, message, score, trace_id, evidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
            params![
                id.to_string(),
                ts.to_rfc3339(),
                agent,
                flag.as_str(),
                message,
                score,
                "{}"
            ],
        )?;
        Ok(id)
    }
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_evidence(raw: Option<String>) -> RiskEvidence {
    raw.as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

fn map_trace_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TraceRecord> {
    let metadata: String = row.get(6)?;
    let start_ts: String = row.get(7)?;
    let end_ts: Option<String> = row.get(8)?;
    Ok(TraceRecord {
        trace_id: row.get(0)?,
        name: row.get(1)?,
        agent: row.get(2)?,
        harness: row.get(3)?,
        user_id: row.get(4)?,
        session_id: row.get(5)?,
        metadata: serde_json::from_str(&metadata).unwrap_or_default(),
        start_ts: parse_ts(&start_ts),
        end_ts: end_ts.as_deref().map(parse_ts),
    })
}

fn map_flag_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FlagRow> {
    let ts: String = row.get(1)?;
    let evidence_raw: Option<String> = row.get(7)?;
    Ok(FlagRow {
        id: row.get(0)?,
        ts: parse_ts(&ts),
        agent: row.get(2)?,
        flag: row.get(3)?,
        message: row.get(4)?,
        score: row.get(5)?,
        trace_id: row.get(6)?,
        evidence: parse_evidence(evidence_raw),
    })
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
        EventKind::Span(_) => "span",
        EventKind::ResourceDelta(_) => "resource_delta",
        EventKind::PolicyDecision(_) => "policy_decision",
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
        assert_eq!(stats.traces, 0);
    }
}
