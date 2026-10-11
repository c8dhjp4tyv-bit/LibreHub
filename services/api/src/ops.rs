//! Operator telemetry: bounded Prometheus metrics, request correlation and health classification.
//!
//! Label values come from fixed vocabularies only: route templates, status classes, queue names
//! and the states the code itself writes. Build, publication, developer and token identifiers and
//! any user-provided string are never label values, so cardinality stays bounded.
use crate::{
    automation_worker::AutomationWorker, catalog_worker::CatalogWorker,
    outbound_worker::OutboundWorker, security_worker::SecurityWorker, store::Store,
};
use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use std::{
    collections::BTreeMap,
    fmt::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const REQUEST_ID_HEADER: &str = "x-request-id";
/// One worker's status: name, ready, the reason it stopped itself (if any), failures by category.
type WorkerStatus = (
    &'static str,
    bool,
    Option<&'static str>,
    Vec<(&'static str, u64)>,
);
const LATENCY_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Clone, Default)]
struct RouteStats {
    classes: [u64; 5],
    buckets: [u64; 11],
    count: u64,
    sum: f64,
}

/// HTTP request telemetry keyed by route template. A request that matches no route is `unmatched`.
#[derive(Default)]
pub struct Telemetry {
    routes: Mutex<BTreeMap<String, RouteStats>>,
    started: Option<Instant>,
}
impl Telemetry {
    pub fn new() -> Self {
        Self {
            routes: Mutex::default(),
            started: Some(Instant::now()),
        }
    }
    pub fn record(&self, route: &str, status: u16, elapsed: Duration) {
        let class = (usize::from(status / 100)).clamp(1, 5) - 1;
        let seconds = elapsed.as_secs_f64();
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let stats = routes.entry(route.to_owned()).or_default();
        stats.classes[class] += 1;
        stats.count += 1;
        stats.sum += seconds;
        if let Some(index) = LATENCY_BUCKETS.iter().position(|bound| seconds <= *bound) {
            stats.buckets[index] += 1;
        }
    }
    fn render_http(&self, out: &mut String) {
        let routes = self
            .routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        header(
            out,
            "librehub_http_requests_total",
            "counter",
            "HTTP requests by route template and status class.",
        );
        for (route, stats) in &routes {
            for (index, count) in stats.classes.iter().enumerate() {
                let class = format!("{}xx", index + 1);
                sample(
                    out,
                    "librehub_http_requests_total",
                    &[("route", route), ("status_class", &class)],
                    *count as f64,
                );
            }
        }
        header(
            out,
            "librehub_http_request_duration_seconds",
            "histogram",
            "HTTP request latency by route template.",
        );
        for (route, stats) in &routes {
            let mut cumulative = 0;
            for (bound, count) in LATENCY_BUCKETS.iter().zip(stats.buckets.iter()) {
                cumulative += count;
                let le = bound.to_string();
                sample(
                    out,
                    "librehub_http_request_duration_seconds_bucket",
                    &[("route", route), ("le", &le)],
                    cumulative as f64,
                );
            }
            sample(
                out,
                "librehub_http_request_duration_seconds_bucket",
                &[("route", route), ("le", "+Inf")],
                stats.count as f64,
            );
            sample(
                out,
                "librehub_http_request_duration_seconds_sum",
                &[("route", route)],
                stats.sum,
            );
            sample(
                out,
                "librehub_http_request_duration_seconds_count",
                &[("route", route)],
                stats.count as f64,
            );
        }
        if let Some(started) = self.started {
            header(
                out,
                "librehub_process_uptime_seconds",
                "gauge",
                "Seconds since this API process started.",
            );
            sample(
                out,
                "librehub_process_uptime_seconds",
                &[],
                started.elapsed().as_secs_f64(),
            );
        }
    }
}

/// Correlates a request end to end: a fresh identifier per request (client-supplied values are not
/// trusted), carried in the tracing span and echoed in the response, plus route and latency.
pub async fn observe(
    State(telemetry): State<Arc<Telemetry>>,
    request: Request,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let method = request.method().clone();
    let request_id = uuid::Uuid::new_v4().to_string();
    let span =
        tracing::info_span!("http", request_id = %request_id, route = %route, method = %method);
    let started = Instant::now();
    let mut response = tracing::Instrument::instrument(next.run(request), span.clone()).await;
    let elapsed = started.elapsed();
    telemetry.record(&route, response.status().as_u16(), elapsed);
    if !route.starts_with("/live") {
        let _enter = span.enter();
        tracing::info!(
            status = response.status().as_u16(),
            duration_ms = elapsed.as_millis() as u64,
            "request finished"
        );
    }
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

/// Queue depths and backlog read from the control-plane database at scrape time.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OpsSnapshot {
    /// `(queue, state, items)`. Queue and state values are the code's own vocabularies.
    pub queues: Vec<(&'static str, String, i64)>,
    /// Outbox events not yet admitted for outbound delivery.
    pub outbox_backlog: i64,
    pub database_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_available_bytes: u64,
}

impl Store {
    /// Counts per queue state. Bounded: every query groups by a state column and is read-only.
    pub async fn ops_snapshot(
        &self,
        data_dir: PathBuf,
        database_path: PathBuf,
    ) -> anyhow::Result<OpsSnapshot> {
        const QUEUES: [(&str, &str, &str); 8] = [
            ("builds", "builds", "status"),
            ("publications", "publishes", "status"),
            ("automation_runs", "automation_runs", "status"),
            ("automation_approvals", "automation_approvals", "status"),
            ("security_analyses", "security_jobs", "state"),
            ("attestations", "attestation_jobs", "state"),
            ("catalog_indexing", "catalog_jobs", "state"),
            ("webhook_deliveries", "integration_deliveries", "status"),
        ];
        let mut snapshot = self
            .run(move |db| {
                let mut snapshot = OpsSnapshot::default();
                for (queue, table, column) in QUEUES {
                    let mut query = db.prepare(&format!("SELECT {column}, count(*) FROM {table} GROUP BY {column}"))?;
                    let rows = query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                    for row in rows {
                        let (state, count) = row?;
                        snapshot.queues.push((queue, state, count));
                    }
                }
                snapshot.outbox_backlog = db.query_row(
                    "SELECT count(*) FROM event_outbox WHERE seq>COALESCE((SELECT last_seq FROM outbox_cursors WHERE consumer='webhooks'),0)",
                    [],
                    |r| r.get(0),
                )?;
                Ok(snapshot)
            })
            .await?;
        let size = |path: &PathBuf| std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let wal = PathBuf::from(format!("{}-wal", database_path.display()));
        snapshot.database_bytes = size(&database_path) + size(&wal);
        snapshot.disk_total_bytes = fs2::total_space(&data_dir).unwrap_or(0);
        snapshot.disk_available_bytes = fs2::available_space(&data_dir).unwrap_or(0);
        Ok(snapshot)
    }
}

/// Worker state for readiness and metrics. `None` means the worker is not part of this process.
#[derive(Clone)]
pub struct OpsState {
    pub store: Store,
    pub telemetry: Arc<Telemetry>,
    pub database_path: PathBuf,
    pub outbound: Option<OutboundWorker>,
    pub automation: Option<AutomationWorker>,
    pub catalog: Option<CatalogWorker>,
    pub security: Option<SecurityWorker>,
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}
fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (index, (key, value)) in labels.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = write!(out, "{key}=\"{escaped}\"");
        }
        out.push('}');
    }
    let _ = writeln!(out, " {value}");
}

/// Render the Prometheus text exposition. Pure: the caller supplies the snapshot and worker flags.
pub fn render(
    telemetry: &Telemetry,
    snapshot: &OpsSnapshot,
    workers: &[WorkerStatus],
    ready: bool,
) -> String {
    let mut out = String::new();
    header(
        &mut out,
        "librehub_build_info",
        "gauge",
        "Build information; the value is always 1.",
    );
    sample(
        &mut out,
        "librehub_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1.0,
    );
    header(
        &mut out,
        "librehub_database_ready",
        "gauge",
        "1 when the control-plane database is ready; full readiness is reported by /ready.",
    );
    sample(
        &mut out,
        "librehub_database_ready",
        &[],
        f64::from(u8::from(ready)),
    );
    telemetry.render_http(&mut out);
    header(
        &mut out,
        "librehub_queue_items",
        "gauge",
        "Items per durable queue and state.",
    );
    for (queue, state, count) in &snapshot.queues {
        sample(
            &mut out,
            "librehub_queue_items",
            &[("queue", queue), ("state", state)],
            *count as f64,
        );
    }
    header(
        &mut out,
        "librehub_outbox_backlog_events",
        "gauge",
        "Transactional outbox events not yet admitted for webhook delivery.",
    );
    sample(
        &mut out,
        "librehub_outbox_backlog_events",
        &[],
        snapshot.outbox_backlog as f64,
    );
    header(
        &mut out,
        "librehub_worker_ready",
        "gauge",
        "1 when a background worker is running and not degraded.",
    );
    header(
        &mut out,
        "librehub_worker_degraded",
        "gauge",
        "1 when a background worker has stopped itself for a stated reason.",
    );
    header(
        &mut out,
        "librehub_webhook_failures_total",
        "counter",
        "Outbound webhook failures by stable category.",
    );
    for (worker, ready, degraded, failures) in workers {
        sample(
            &mut out,
            "librehub_worker_ready",
            &[("worker", worker)],
            f64::from(u8::from(*ready)),
        );
        if let Some(reason) = degraded {
            sample(
                &mut out,
                "librehub_worker_degraded",
                &[("worker", worker), ("reason", reason)],
                1.0,
            );
        }
        if *worker == "outbound" {
            for (category, count) in failures {
                sample(
                    &mut out,
                    "librehub_webhook_failures_total",
                    &[("category", category)],
                    *count as f64,
                );
            }
        }
    }
    header(
        &mut out,
        "librehub_database_bytes",
        "gauge",
        "Control-plane SQLite file plus its write-ahead log.",
    );
    sample(
        &mut out,
        "librehub_database_bytes",
        &[],
        snapshot.database_bytes as f64,
    );
    header(
        &mut out,
        "librehub_disk_total_bytes",
        "gauge",
        "Total capacity of the data directory file system.",
    );
    sample(
        &mut out,
        "librehub_disk_total_bytes",
        &[],
        snapshot.disk_total_bytes as f64,
    );
    header(
        &mut out,
        "librehub_disk_available_bytes",
        "gauge",
        "Bytes available to the API on the data directory file system.",
    );
    sample(
        &mut out,
        "librehub_disk_available_bytes",
        &[],
        snapshot.disk_available_bytes as f64,
    );
    out
}

async fn collect(state: &OpsState, data_dir: PathBuf) -> Result<String, anyhow::Error> {
    let database = state.store.database_ready().await;
    let snapshot = state
        .store
        .ops_snapshot(data_dir, state.database_path.clone())
        .await?;
    let mut workers: Vec<WorkerStatus> = vec![];
    if let Some(outbound) = &state.outbound {
        workers.push((
            "outbound",
            outbound.ready(),
            outbound.health.degraded(),
            outbound.health.failures(),
        ));
    }
    if let Some(automation) = &state.automation {
        workers.push(("automation", automation.ready(), None, vec![]));
    }
    if let Some(catalog) = &state.catalog {
        workers.push(("catalog", catalog.ready().await, None, vec![]));
    }
    if let Some(security) = &state.security {
        workers.push(("security", security.ready().await, None, vec![]));
    }
    let mut output = render(&state.telemetry, &snapshot, &workers, database);
    if let Some(automation) = &state.automation {
        header(
            &mut output,
            "librehub_automation_outbox_failures_total",
            "counter",
            "Failed automation outbox consumption attempts.",
        );
        sample(
            &mut output,
            "librehub_automation_outbox_failures_total",
            &[],
            automation
                .outbox_failures
                .load(std::sync::atomic::Ordering::Relaxed) as f64,
        );
    }
    Ok(output)
}

async fn metrics(State(state): State<OpsState>) -> Response {
    let data_dir = state.store.data_dir.clone();
    match collect(&state, data_dir).await {
        Ok(body) => (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "Metrics collection failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Metrics are served only on the operator listener (`LIBREHUB_METRICS_BIND`), never on the
/// public router, so the reverse proxy has no route to them.
pub fn metrics_router(state: OpsState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Liveness: this process is serving HTTP. It never checks dependencies; that is readiness.
pub async fn live() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"status":"live","version":env!("CARGO_PKG_VERSION")})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_escaped_and_histograms_are_cumulative() {
        let telemetry = Telemetry::new();
        telemetry.record("/api/v1/projects/{id}", 200, Duration::from_millis(3));
        telemetry.record("/api/v1/projects/{id}", 500, Duration::from_millis(40));
        telemetry.record("unmatched", 404, Duration::from_secs(20));
        let text = render(&telemetry, &OpsSnapshot::default(), &[], true);
        assert!(text.contains(
            r#"librehub_http_requests_total{route="/api/v1/projects/{id}",status_class="2xx"} 1"#
        ));
        assert!(text.contains(
            r#"librehub_http_requests_total{route="/api/v1/projects/{id}",status_class="5xx"} 1"#
        ));
        assert!(text.contains(r#"librehub_http_request_duration_seconds_bucket{route="/api/v1/projects/{id}",le="0.005"} 1"#));
        assert!(text.contains(r#"librehub_http_request_duration_seconds_bucket{route="/api/v1/projects/{id}",le="0.05"} 2"#));
        assert!(text.contains(
            r#"librehub_http_request_duration_seconds_bucket{route="unmatched",le="+Inf"} 1"#
        ));
        assert!(text.contains("librehub_database_ready 1"));
        let mut escaped = String::new();
        sample(&mut escaped, "m", &[("route", "a\"b\\c")], 1.0);
        assert_eq!(escaped, "m{route=\"a\\\"b\\\\c\"} 1\n");
    }

    #[test]
    fn worker_failures_are_exported_by_stable_category_only() {
        let text = render(
            &Telemetry::new(),
            &OpsSnapshot::default(),
            &[(
                "outbound",
                false,
                Some("storage_corrupt"),
                vec![("task_panic", 2)],
            )],
            false,
        );
        assert!(
            text.contains(
                r#"librehub_worker_degraded{worker="outbound",reason="storage_corrupt"} 1"#
            )
        );
        assert!(text.contains(r#"librehub_webhook_failures_total{category="task_panic"} 2"#));
        assert!(text.contains("librehub_database_ready 0"));
    }
}
