use std::{
    collections::BTreeMap,
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Local, TimeZone};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use rand::{Rng, distributions::Alphanumeric};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    net::TcpListener,
    sync::Mutex,
    time::{MissedTickBehavior, interval},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

type HostsByIp = BTreeMap<IpAddr, BTreeMap<String, HostEntry>>;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    store: Arc<Mutex<Store>>,
}

struct Store {
    hosts: HostsByIp,
    last_no_pending_log_at: Option<Instant>,
}

#[derive(Clone, Debug)]
struct Config {
    target: PathBuf,
    tmp_dir: PathBuf,
    flush_interval_ms: u64,
    bind: String,
    port: u16,
    basic_auth: Option<BasicAuthConfig>,
    dnsmasq_pid_file: PathBuf,
    db_file: PathBuf,
}

#[derive(Clone, Debug)]
struct BasicAuthConfig {
    username: String,
    password: String,
}

#[derive(Clone, Debug)]
struct HostEntry {
    ttl_seconds: u64,
    registered_at_epoch_secs: i64,
}

#[derive(Deserialize, Debug)]
struct AddHostRequest {
    ip: IpAddr,
    host: String,
    replace: bool,
    #[serde(default, alias = "ttl_seconds")]
    ttl: Option<u64>,
}

#[derive(Serialize)]
struct RemovedHostCount {
    removed_host_count: usize,
}

#[derive(Serialize)]
struct MessageResponse {
    message: String,
}

#[derive(Serialize)]
struct HostsResponse {
    ip: String,
    hosts: Vec<String>,
}

#[derive(Serialize)]
struct HostView {
    name: String,
    ttl_seconds: u64,
    registered_time: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_string(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(MessageResponse {
            message: self.message,
        });

        if self.status == StatusCode::UNAUTHORIZED {
            (
                self.status,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"dnsmasq-agent\"")],
                body,
            )
                .into_response()
        } else {
            (self.status, body).into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let config_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dnsmasq-agent.conf"));
    let config = Arc::new(load_config(&config_path).context("failed to load config")?);
    init_db(&config.db_file)?;
    let initial_hosts = load_hosts_from_db(&config.db_file)?;

    info!(
        config = %config_path.display(),
        target = %config.target.display(),
        tmp_dir = %config.tmp_dir.display(),
        db_file = %config.db_file.display(),
        bind = %config.bind,
        port = config.port,
        flush_interval_ms = config.flush_interval_ms,
        "starting dnsmasq agent"
    );

    let state = AppState {
        config: Arc::clone(&config),
        store: Arc::new(Mutex::new(Store {
            hosts: initial_hosts,
            last_no_pending_log_at: None,
        })),
    };

    tokio::spawn(flush_loop(state.clone()));

    let app = Router::new()
        .route("/dnsmasq/", get(ui_redirect))
        .route("/dnsmasq/add_host", post(add_host))
        .route("/dnsmasq/all", get(list_all))
        .route("/dnsmasq/export_now", post(export_now))
        .route("/dnsmasq/index.html", get(ui_redirect))
        .route("/dnsmasq/ui/index.html", get(ui_index))
        .route("/dnsmasq/{ip}", delete(delete_ip))
        .route("/dnsmasq/{ip}/{host}", delete(delete_host))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .with_context(|| format!("invalid bind address {}:{}", config.bind, config.port))?;
    let listener = TcpListener::bind(addr).await?;
    info!(listen = %addr, "http server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("dnsmasq_agent=debug,info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn ui_redirect() -> Redirect {
    Redirect::temporary("/dnsmasq/ui/index.html")
}

async fn ui_index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    ensure_authorized(&state.config, &headers)?;
    let csrf_token = generate_csrf_token();
    let cookie = format!(
        "dnsmasq_csrf={}; Path=/dnsmasq; HttpOnly; SameSite=Strict",
        csrf_token
    );
    Ok((
        [(header::SET_COOKIE, cookie)],
        Html(render_ui_html(&csrf_token)),
    ))
}

async fn add_host(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AddHostRequest>,
) -> Result<Json<HostsResponse>, ApiError> {
    ensure_authorized(&state.config, &headers)?;
    ensure_csrf(&headers)?;
    let host = normalize_host_for_api(&payload.host)?;
    let ttl_seconds = payload.ttl.unwrap_or(0);
    let now = now_epoch_secs();

    let mut store = state.store.lock().await;
    let mut conn = open_db(&state.config.db_file).map_err(internal_api_error)?;
    purge_expired_and_refresh(&mut conn, &state.config.db_file, &mut store)
        .map_err(internal_api_error)?;

    let tx = conn
        .transaction()
        .map_err(|error| internal_api_error(error.into()))?;
    if payload.replace {
        tx.execute(
            "DELETE FROM hosts WHERE ip = ?1",
            params![payload.ip.to_string()],
        )
        .map_err(|error| internal_api_error(error.into()))?;
    }
    tx.execute(
        "INSERT INTO hosts (ip, host, ttl_seconds, registered_at_epoch_secs)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(ip, host) DO UPDATE SET
           ttl_seconds = excluded.ttl_seconds,
           registered_at_epoch_secs = excluded.registered_at_epoch_secs",
        params![payload.ip.to_string(), host, ttl_seconds as i64, now],
    )
    .map_err(|error| internal_api_error(error.into()))?;
    bump_db_generation(&tx).map_err(internal_api_error)?;
    tx.commit()
        .map_err(|error| internal_api_error(error.into()))?;

    store.hosts = load_hosts_from_db(&state.config.db_file).map_err(internal_api_error)?;
    let hosts = store
        .hosts
        .get(&payload.ip)
        .map(|entries| entries.keys().cloned().collect())
        .unwrap_or_default();

    info!(
        ip = %payload.ip,
        host = %host,
        replace = payload.replace,
        ttl_seconds,
        "api add_host"
    );

    Ok(Json(HostsResponse {
        ip: payload.ip.to_string(),
        hosts,
    }))
}

async fn delete_ip(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(ip): AxumPath<IpAddr>,
) -> Result<Json<RemovedHostCount>, ApiError> {
    ensure_authorized(&state.config, &headers)?;
    ensure_csrf(&headers)?;

    let mut store = state.store.lock().await;
    let mut conn = open_db(&state.config.db_file).map_err(internal_api_error)?;
    purge_expired_and_refresh(&mut conn, &state.config.db_file, &mut store)
        .map_err(internal_api_error)?;

    let removed = conn
        .execute("DELETE FROM hosts WHERE ip = ?1", params![ip.to_string()])
        .map_err(|error| internal_api_error(error.into()))?;
    if removed > 0 {
        bump_db_generation(&conn).map_err(internal_api_error)?;
        store.hosts = load_hosts_from_db(&state.config.db_file).map_err(internal_api_error)?;
    }

    info!(ip = %ip, removed_host_count = removed, "api delete_ip");
    Ok(Json(RemovedHostCount {
        removed_host_count: removed,
    }))
}

async fn delete_host(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((ip, host)): AxumPath<(IpAddr, String)>,
) -> Result<Json<RemovedHostCount>, ApiError> {
    ensure_authorized(&state.config, &headers)?;
    ensure_csrf(&headers)?;
    let host = normalize_host_for_api(&host)?;

    let mut store = state.store.lock().await;
    let mut conn = open_db(&state.config.db_file).map_err(internal_api_error)?;
    purge_expired_and_refresh(&mut conn, &state.config.db_file, &mut store)
        .map_err(internal_api_error)?;

    let removed = conn
        .execute(
            "DELETE FROM hosts WHERE ip = ?1 AND host = ?2",
            params![ip.to_string(), host],
        )
        .map_err(|error| internal_api_error(error.into()))?;
    if removed > 0 {
        bump_db_generation(&conn).map_err(internal_api_error)?;
        store.hosts = load_hosts_from_db(&state.config.db_file).map_err(internal_api_error)?;
    }

    info!(
        ip = %ip,
        host = %host,
        removed_host_count = removed,
        "api delete_host"
    );
    Ok(Json(RemovedHostCount {
        removed_host_count: removed,
    }))
}

async fn list_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BTreeMap<String, Vec<HostView>>>, ApiError> {
    ensure_authorized(&state.config, &headers)?;

    let mut store = state.store.lock().await;
    let mut conn = open_db(&state.config.db_file).map_err(internal_api_error)?;
    purge_expired_and_refresh(&mut conn, &state.config.db_file, &mut store)
        .map_err(internal_api_error)?;

    let response = serialize_hosts_map(&store.hosts);
    info!(entry_count = response.len(), "api list_all");
    Ok(Json(response))
}

async fn export_now(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MessageResponse>, ApiError> {
    ensure_authorized(&state.config, &headers)?;
    ensure_csrf(&headers)?;
    force_export_now(&state).await.map_err(internal_api_error)?;
    Ok(Json(MessageResponse {
        message: "export completed".to_string(),
    }))
}

async fn flush_loop(state: AppState) {
    let mut ticker = interval(Duration::from_millis(state.config.flush_interval_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        if let Err(error) = flush_once(&state).await {
            error!(error = %error, "flush attempt failed");
        }
    }
}

async fn flush_once(state: &AppState) -> Result<()> {
    let snapshot = {
        let mut store = state.store.lock().await;
        let mut conn = open_db(&state.config.db_file)?;
        purge_expired_and_refresh(&mut conn, &state.config.db_file, &mut store)?;
        let (db_generation, file_generation) = get_generations(&conn)?;
        if db_generation == file_generation {
            maybe_log_no_pending(&mut store, db_generation, file_generation);
            return Ok(());
        }

        FlushSnapshot {
            hosts: store.hosts.clone(),
            db_generation,
        }
    };

    info!(
        target = %state.config.target.display(),
        db_generation = snapshot.db_generation,
        "flush attempt started"
    );

    let rendered = render_hosts(&snapshot.hosts);
    let replace_happened =
        write_hosts_file_if_changed(&state.config.target, &state.config.tmp_dir, &rendered).await?;
    if replace_happened {
        try_send_hup_signal(&state.config.dnsmasq_pid_file).await;
        let mut store = state.store.lock().await;
        reset_no_pending_log_suppression(&mut store);
    } else {
        info!(
            db_generation = snapshot.db_generation,
            "rendered hosts file identical; skipping replace and SIGHUP"
        );
    }

    let conn = open_db(&state.config.db_file)?;
    set_file_generation(&conn, snapshot.db_generation)?;

    info!(
        db_generation = snapshot.db_generation,
        replace_happened, "flush attempt completed"
    );
    Ok(())
}

async fn force_export_now(state: &AppState) -> Result<()> {
    let snapshot = {
        let mut store = state.store.lock().await;
        let mut conn = open_db(&state.config.db_file)?;
        purge_expired_and_refresh(&mut conn, &state.config.db_file, &mut store)?;
        let (db_generation, _) = get_generations(&conn)?;

        FlushSnapshot {
            hosts: store.hosts.clone(),
            db_generation,
        }
    };

    info!(
        target = %state.config.target.display(),
        db_generation = snapshot.db_generation,
        "force export started"
    );

    let rendered = render_hosts(&snapshot.hosts);
    write_hosts_file_force(&state.config.target, &state.config.tmp_dir, &rendered).await?;
    try_send_hup_signal(&state.config.dnsmasq_pid_file).await;
    {
        let mut store = state.store.lock().await;
        reset_no_pending_log_suppression(&mut store);
    }

    let conn = open_db(&state.config.db_file)?;
    set_file_generation(&conn, snapshot.db_generation)?;

    info!(
        db_generation = snapshot.db_generation,
        "force export completed"
    );
    Ok(())
}

#[derive(Clone)]
struct FlushSnapshot {
    hosts: HostsByIp,
    db_generation: i64,
}

fn load_config(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let mut values = BTreeMap::new();

    for (line_no, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!(
                "invalid config at {}:{}: expected key=value",
                path.display(),
                line_no + 1
            );
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok(Config {
        target: PathBuf::from(required_config(&values, "target")?),
        tmp_dir: PathBuf::from(required_config(&values, "tmp_dir")?),
        flush_interval_ms: required_config(&values, "flush_interval_ms")?
            .parse()
            .context("invalid flush_interval_ms")?,
        bind: required_config(&values, "bind")?.to_string(),
        port: required_config(&values, "port")?
            .parse()
            .context("invalid port")?,
        basic_auth: values
            .get("basic_auth")
            .map(|raw| parse_basic_auth(raw))
            .transpose()?,
        dnsmasq_pid_file: PathBuf::from(required_config(&values, "dnsmasq_pid_file")?),
        db_file: PathBuf::from(required_config(&values, "db_file")?),
    })
}

fn required_config<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing required config key `{key}`"))
}

fn parse_basic_auth(raw: &str) -> Result<BasicAuthConfig> {
    let Some((username, password)) = raw.split_once(':') else {
        bail!("basic_auth must be username:password");
    };
    Ok(BasicAuthConfig {
        username: username.to_string(),
        password: password.to_string(),
    })
}

fn ensure_csrf(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(cookie_token) = get_cookie(headers, "dnsmasq_csrf") else {
        return Ok(());
    };
    let Some(header_token) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: "csrf validation failed".to_string(),
        });
    };
    if header_token == cookie_token {
        Ok(())
    } else {
        Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: "csrf validation failed".to_string(),
        })
    }
}

fn ensure_authorized(config: &Config, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(auth) = &config.basic_auth else {
        return Ok(());
    };
    let Some(header_value) = headers.get(header::AUTHORIZATION) else {
        return Err(ApiError::unauthorized());
    };
    let Ok(header_value) = header_value.to_str() else {
        return Err(ApiError::unauthorized());
    };
    let Some(encoded) = header_value.strip_prefix("Basic ") else {
        return Err(ApiError::unauthorized());
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return Err(ApiError::unauthorized());
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return Err(ApiError::unauthorized());
    };
    let Some((username, password)) = decoded.split_once(':') else {
        return Err(ApiError::unauthorized());
    };
    if username == auth.username && password == auth.password {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

fn init_db(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create db parent directory {}", parent.display())
        })?;
    }

    let conn = open_db(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT NOT NULL,
            host TEXT NOT NULL,
            ttl_seconds INTEGER NOT NULL DEFAULT 0,
            registered_at_epoch_secs INTEGER NOT NULL,
            PRIMARY KEY (ip, host)
        );
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );",
    )
    .context("failed to initialize sqlite schema")?;
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('db_generation', 0)
         ON CONFLICT(key) DO NOTHING",
        [],
    )
    .context("failed to initialize db_generation")?;
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('file_generation', 0)
         ON CONFLICT(key) DO NOTHING",
        [],
    )
    .context("failed to initialize file_generation")?;
    Ok(())
}

fn open_db(path: &Path) -> Result<Connection> {
    Connection::open(path).with_context(|| format!("failed to open sqlite db {}", path.display()))
}

fn load_hosts_from_db(path: &Path) -> Result<HostsByIp> {
    let conn = open_db(path)?;
    let mut stmt = conn.prepare(
        "SELECT ip, host, ttl_seconds, registered_at_epoch_secs
         FROM hosts
         ORDER BY ip ASC, host ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut hosts = HostsByIp::new();

    while let Some(row) = rows.next()? {
        let ip_raw: String = row.get(0)?;
        let host: String = row.get(1)?;
        let ttl_seconds: i64 = row.get(2)?;
        let registered_at_epoch_secs: i64 = row.get(3)?;
        let ip: IpAddr = ip_raw
            .parse()
            .with_context(|| format!("invalid ip stored in sqlite: {ip_raw}"))?;

        hosts.entry(ip).or_default().insert(
            host,
            HostEntry {
                ttl_seconds: ttl_seconds.max(0) as u64,
                registered_at_epoch_secs,
            },
        );
    }

    Ok(hosts)
}

fn purge_expired_and_refresh(
    conn: &mut Connection,
    db_path: &Path,
    store: &mut Store,
) -> Result<()> {
    let now = now_epoch_secs();
    let removed = conn.execute(
        "DELETE FROM hosts
         WHERE ttl_seconds > 0
           AND registered_at_epoch_secs + ttl_seconds <= ?1",
        params![now],
    )?;
    if removed > 0 {
        bump_db_generation(conn)?;
        info!(
            removed_host_count = removed,
            "expired ttl hosts removed from sqlite"
        );
        store.hosts = load_hosts_from_db(db_path)?;
    }
    Ok(())
}

fn render_hosts(hosts: &HostsByIp) -> String {
    let mut lines = Vec::new();
    for (ip, names) in hosts {
        if names.is_empty() {
            continue;
        }
        lines.push(format!(
            "{} {}",
            ip,
            names.keys().cloned().collect::<Vec<_>>().join(" ")
        ));
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn serialize_hosts_map(hosts: &HostsByIp) -> BTreeMap<String, Vec<HostView>> {
    hosts
        .iter()
        .map(|(ip, entries)| {
            let values = entries
                .iter()
                .map(|(name, entry)| HostView {
                    name: name.clone(),
                    ttl_seconds: entry.ttl_seconds,
                    registered_time: format_registered_time(entry.registered_at_epoch_secs),
                })
                .collect();
            (ip.to_string(), values)
        })
        .collect()
}

fn normalize_host_for_api(host: &str) -> Result<String, ApiError> {
    normalize_host(host).map_err(|error| ApiError::bad_request(error.to_string()))
}

fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        bail!("host must not be empty");
    }
    Ok(host)
}

fn format_registered_time(epoch_secs: i64) -> String {
    match Local.timestamp_opt(epoch_secs, 0).single() {
        Some(value) => value.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        None => epoch_secs.to_string(),
    }
}

async fn write_hosts_file_if_changed(
    target: &Path,
    tmp_dir: &Path,
    rendered: &str,
) -> Result<bool> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create target parent directory {}",
                parent.display()
            )
        })?;
    }
    fs::create_dir_all(tmp_dir)
        .await
        .with_context(|| format!("failed to create tmp_dir {}", tmp_dir.display()))?;

    let file_name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("target file name is not valid utf-8"))?;
    let tmp_path = tmp_dir.join(format!("{file_name}.tmp"));
    fs::write(&tmp_path, rendered)
        .await
        .with_context(|| format!("failed to write temp file {}", tmp_path.display()))?;

    let existing = match fs::read(target).await {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", target.display()));
        }
    };

    if existing.as_deref() == Some(rendered.as_bytes()) {
        fs::remove_file(&tmp_path).await.with_context(|| {
            format!(
                "failed to remove unchanged temp file {}",
                tmp_path.display()
            )
        })?;
        return Ok(false);
    }

    fs::rename(&tmp_path, target)
        .await
        .with_context(|| format!("failed to replace {}", target.display()))?;
    Ok(true)
}

async fn write_hosts_file_force(target: &Path, tmp_dir: &Path, rendered: &str) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create target parent directory {}",
                parent.display()
            )
        })?;
    }
    fs::create_dir_all(tmp_dir)
        .await
        .with_context(|| format!("failed to create tmp_dir {}", tmp_dir.display()))?;

    let file_name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("target file name is not valid utf-8"))?;
    let tmp_path = tmp_dir.join(format!("{file_name}.tmp"));
    fs::write(&tmp_path, rendered)
        .await
        .with_context(|| format!("failed to write temp file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, target)
        .await
        .with_context(|| format!("failed to replace {}", target.display()))?;
    Ok(())
}

async fn send_hup_signal(pid_file: &Path) -> Result<()> {
    let raw = fs::read_to_string(pid_file)
        .await
        .with_context(|| format!("failed to read pid file {}", pid_file.display()))?;
    let pid: i32 = raw
        .trim()
        .parse()
        .with_context(|| format!("invalid pid in {}", pid_file.display()))?;
    kill(Pid::from_raw(pid), Signal::SIGHUP)
        .with_context(|| format!("failed to send HUP to pid {pid}"))?;
    info!(pid, "sent HUP to dnsmasq");
    Ok(())
}

async fn try_send_hup_signal(pid_file: &Path) {
    if let Err(error) = send_hup_signal(pid_file).await {
        warn!(
            pid_file = %pid_file.display(),
            error = %error,
            "failed to send HUP to dnsmasq; export still completed"
        );
    }
}

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn internal_api_error(error: anyhow::Error) -> ApiError {
    ApiError::internal(error.to_string())
}

fn get_generations(conn: &Connection) -> Result<(i64, i64)> {
    Ok((
        get_metadata_i64(conn, "db_generation")?,
        get_metadata_i64(conn, "file_generation")?,
    ))
}

fn get_metadata_i64(conn: &Connection, key: &str) -> Result<i64> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .with_context(|| format!("failed to read metadata key `{key}`"))
}

fn set_metadata_i64(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "UPDATE metadata SET value = ?2 WHERE key = ?1",
        params![key, value],
    )
    .with_context(|| format!("failed to update metadata key `{key}`"))?;
    Ok(())
}

fn bump_db_generation(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE metadata SET value = value + 1 WHERE key = 'db_generation'",
        [],
    )
    .context("failed to bump db_generation")?;
    Ok(())
}

fn set_file_generation(conn: &Connection, generation: i64) -> Result<()> {
    set_metadata_i64(conn, "file_generation", generation)
}

fn get_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for item in raw.split(';') {
        let item = item.trim();
        let (key, value) = item.split_once('=')?;
        if key == name {
            return Some(value);
        }
    }
    None
}

fn generate_csrf_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn render_ui_html(csrf_token: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DNSMASQ Agent</title>
  <style>
    :root {{
      --bg: #f3efe6;
      --panel: rgba(255,255,255,0.78);
      --panel-strong: rgba(255,255,255,0.92);
      --ink: #1f2a2a;
      --muted: #637070;
      --line: rgba(31,42,42,0.12);
      --accent: #0f766e;
      --accent-2: #dd6b20;
      --danger: #b42318;
      --shadow: 0 24px 60px rgba(36, 44, 53, 0.14);
      --radius: 24px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(15,118,110,0.18), transparent 30%),
        radial-gradient(circle at top right, rgba(221,107,32,0.18), transparent 28%),
        linear-gradient(160deg, #f8f5ee 0%, #efe9dd 48%, #e8efe9 100%);
    }}
    .shell {{
      max-width: 1220px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }}
    .hero {{
      display: grid;
      grid-template-columns: 1.3fr 0.7fr;
      gap: 20px;
      margin-bottom: 20px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }}
    .hero-main {{
      padding: 28px;
    }}
    .hero-main h1 {{
      margin: 0 0 10px;
      font-size: clamp(2rem, 5vw, 4rem);
      line-height: 0.95;
      letter-spacing: -0.05em;
    }}
    .hero-main p {{
      margin: 0;
      max-width: 46rem;
      color: var(--muted);
      font-size: 1rem;
      line-height: 1.6;
    }}
    .hero-side {{
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      justify-content: center;
    }}
    .hero-side .pill {{
      display: inline-flex;
      width: fit-content;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      background: rgba(15,118,110,0.09);
      color: var(--accent);
      padding: 8px 12px;
      font-size: 0.88rem;
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }}
    .hero-side code {{
      font-size: 0.92rem;
      background: rgba(31,42,42,0.06);
      border-radius: 12px;
      padding: 3px 7px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 20px;
    }}
    .span-5 {{ grid-column: span 5; }}
    .span-7 {{ grid-column: span 7; }}
    .panel {{
      padding: 22px;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 1.15rem;
      letter-spacing: -0.03em;
    }}
    .sub {{
      margin: -6px 0 18px;
      color: var(--muted);
      font-size: 0.94rem;
    }}
    .form-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }}
    .field {{
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .field.full {{ grid-column: 1 / -1; }}
    label {{
      font-size: 0.9rem;
      font-weight: 700;
    }}
    input[type="text"],
    input[type="number"] {{
      width: 100%;
      border: 1px solid rgba(31,42,42,0.12);
      background: var(--panel-strong);
      color: var(--ink);
      border-radius: 16px;
      padding: 13px 14px;
      outline: none;
      font: inherit;
      transition: border-color 120ms ease, transform 120ms ease;
    }}
    input:focus {{
      border-color: rgba(15,118,110,0.55);
      transform: translateY(-1px);
    }}
    .check {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding-top: 8px;
    }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}
    button {{
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: transform 120ms ease, opacity 120ms ease, box-shadow 120ms ease;
    }}
    button:hover {{
      transform: translateY(-1px);
    }}
    button:disabled {{
      opacity: 0.55;
      cursor: wait;
      transform: none;
    }}
    .primary {{
      background: linear-gradient(135deg, #0f766e, #115e59);
      color: white;
      box-shadow: 0 14px 28px rgba(15,118,110,0.22);
    }}
    .secondary {{
      background: linear-gradient(135deg, #dd6b20, #c05621);
      color: white;
    }}
    .ghost {{
      background: rgba(31,42,42,0.06);
      color: var(--ink);
    }}
    .danger {{
      background: rgba(180,35,24,0.1);
      color: var(--danger);
    }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 18px;
    }}
    .status {{
      min-height: 52px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.52);
      padding: 14px 16px;
      font-size: 0.94rem;
      color: var(--muted);
      white-space: pre-wrap;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      opacity: 1;
      transition: opacity 240ms ease, transform 240ms ease;
    }}
    .status.good {{
      color: #0b5f57;
      background: rgba(15,118,110,0.08);
      border-color: rgba(15,118,110,0.18);
    }}
    .status.bad {{
      color: var(--danger);
      background: rgba(180,35,24,0.08);
      border-color: rgba(180,35,24,0.18);
    }}
    .status.hidden {{
      opacity: 0;
      transform: translateY(-4px);
      pointer-events: none;
    }}
    .status button {{
      padding: 7px 10px;
      background: rgba(31,42,42,0.06);
      color: var(--ink);
      font-size: 0.82rem;
      box-shadow: none;
      flex-shrink: 0;
    }}
    .status-message {{
      min-width: 0;
    }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255,255,255,0.62);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 760px;
    }}
    th, td {{
      padding: 14px 16px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid rgba(31,42,42,0.08);
    }}
    th {{
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      background: rgba(31,42,42,0.03);
    }}
    td code {{
      font-size: 0.9rem;
      background: rgba(31,42,42,0.06);
      border-radius: 10px;
      padding: 3px 6px;
    }}
    .row-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .empty {{
      padding: 24px;
      color: var(--muted);
    }}
    @media (max-width: 980px) {{
      .hero, .grid {{
        grid-template-columns: 1fr;
      }}
      .span-5, .span-7 {{
        grid-column: auto;
      }}
      .form-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="card hero-main">
        <h1>DNSMASQ Agent</h1>
        <p>Operate the SQLite-backed host registry, inspect active entries, and trigger exports without dropping into curl. All write actions reuse the same API surface as your automation.</p>
      </div>
      <aside class="card hero-side">
        <div class="pill">Live Control Surface</div>
        <div>UI path: <code>/dnsmasq/ui/index.html</code></div>
        <div>CSRF token is embedded into this page and validated on mutating AJAX requests.</div>
        <div>Current time: <code id="live-time">--:--:--</code></div>
        <div>Auto refresh: <code>every 5 seconds</code></div>
        <div class="actions" style="margin-top:4px;">
          <button class="ghost" type="button" id="live-refresh">Refresh</button>
        </div>
      </aside>
    </section>

    <section class="grid">
      <div class="card panel span-5">
        <h2>Add Or Replace Host</h2>
        <p class="sub">Use the same semantics as <code>POST /dnsmasq/add_host</code>. Re-posting the same host refreshes TTL and registration time.</p>
        <form id="add-form">
          <div class="form-grid">
            <div class="field">
              <label for="ip">IP Address</label>
              <input id="ip" name="ip" type="text" placeholder="10.2.2.2" required>
            </div>
            <div class="field">
              <label for="host">Hostname</label>
              <input id="host" name="host" type="text" placeholder="service.example.test" required>
            </div>
            <div class="field">
              <label for="ttl">TTL Seconds</label>
              <input id="ttl" name="ttl" type="number" min="0" placeholder="0 means forever">
            </div>
            <div class="field check">
              <input id="replace" name="replace" type="checkbox">
              <label for="replace">Replace all hosts under this IP</label>
            </div>
          </div>
          <div class="actions">
            <button class="primary" type="submit" id="add-submit">Submit Change</button>
          </div>
        </form>
      </div>

      <div class="card panel span-7">
        <h2>Operations</h2>
        <p class="sub">Background export respects generation and diff checks. Force export bypasses both and always syncs the current rendered state.</p>
        <div class="toolbar">
          <button class="secondary" type="button" id="export-now">Force Export Now</button>
        </div>
        <div id="status" class="status hidden">
          <div id="status-message" class="status-message">Ready.</div>
          <button type="button" id="status-close">Dismiss</button>
        </div>
      </div>
    </section>

    <section class="card panel" style="margin-top:20px;">
      <h2>Active Hosts</h2>
      <p class="sub">Entries are grouped by IP and rendered from <code>GET /dnsmasq/all</code>. Delete operations below call the existing API endpoints directly.</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th>Host</th>
              <th>TTL</th>
              <th>Registered</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="hosts-body">
            <tr><td colspan="5" class="empty">Loading active hosts...</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const csrfToken = {csrf_token:?};
    const statusEl = document.getElementById('status');
    const statusMessageEl = document.getElementById('status-message');
    const statusCloseEl = document.getElementById('status-close');
    const hostsBody = document.getElementById('hosts-body');
    const addForm = document.getElementById('add-form');
    const addSubmit = document.getElementById('add-submit');
    const liveTimeEl = document.getElementById('live-time');
    let refreshTimer = null;
    let statusTimer = null;

    function hideStatus() {{
      statusEl.classList.add('hidden');
    }}

    function setStatus(message, tone = '', autoHide = false) {{
      if (statusTimer) {{
        clearTimeout(statusTimer);
        statusTimer = null;
      }}
      statusEl.className = 'status' + (tone ? ' ' + tone : '');
      statusMessageEl.textContent = message;
      statusEl.classList.remove('hidden');
      if (autoHide) {{
        statusTimer = setTimeout(() => {{
          hideStatus();
          statusTimer = null;
        }}, 3000);
      }}
    }}

    function updateClock() {{
      liveTimeEl.textContent = new Date().toLocaleString();
    }}

    function humanTimestamp() {{
      return new Date().toLocaleString();
    }}

    async function api(path, options = {{}}) {{
      const headers = new Headers(options.headers || {{}});
      if (options.csrf) {{
        headers.set('X-CSRF-Token', csrfToken);
      }}
      const response = await fetch(path, {{
        credentials: 'same-origin',
        ...options,
        headers,
      }});
      const text = await response.text();
      let data = null;
      try {{
        data = text ? JSON.parse(text) : null;
      }} catch {{
        data = text;
      }}
      if (!response.ok) {{
        const message = data && data.message ? data.message : (typeof data === 'string' ? data : response.statusText);
        throw new Error(message || 'Request failed');
      }}
      return data;
    }}

    function renderHosts(payload) {{
      const rows = [];
      const ips = Object.keys(payload || {{}});
      if (ips.length === 0) {{
        hostsBody.innerHTML = '<tr><td colspan="5" class="empty">No active hosts.</td></tr>';
        return;
      }}
      for (const ip of ips) {{
        const entries = payload[ip] || [];
        entries.forEach((entry, index) => {{
          rows.push(`
            <tr>
              <td>${{index === 0 ? `<code>${{ip}}</code>` : ''}}</td>
              <td><code>${{entry.name}}</code></td>
              <td>${{entry.ttl_seconds}}</td>
              <td>${{entry.registered_time}}</td>
              <td>
                <div class="row-actions">
                  <button class="danger" type="button" data-action="delete-host" data-ip="${{ip}}" data-host="${{entry.name}}">Delete Host</button>
                  ${{index === 0 ? `<button class="ghost" type="button" data-action="delete-ip" data-ip="${{ip}}">Delete IP</button>` : ''}}
                </div>
              </td>
            </tr>
          `);
        }});
      }}
      hostsBody.innerHTML = rows.join('');
    }}

    async function refreshHosts(message = 'Refreshing host list...') {{
      setStatus(message);
      const data = await api('/dnsmasq/all');
      renderHosts(data);
      setStatus(`Host list refreshed at ${{humanTimestamp()}}.`, 'good', true);
    }}

    addForm.addEventListener('submit', async (event) => {{
      event.preventDefault();
      addSubmit.disabled = true;
      try {{
        const payload = {{
          ip: document.getElementById('ip').value.trim(),
          host: document.getElementById('host').value.trim(),
          replace: document.getElementById('replace').checked
        }};
        const ttlRaw = document.getElementById('ttl').value.trim();
        if (ttlRaw !== '') {{
          payload.ttl = Number(ttlRaw);
        }}
        const data = await api('/dnsmasq/add_host', {{
          method: 'POST',
          csrf: true,
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload)
        }});
        setStatus(`Updated ${{data.ip}} with hosts: ${{data.hosts.join(', ') || '(none)'}} at ${{humanTimestamp()}}.`, 'good', true);
        await refreshHosts();
      }} catch (error) {{
        setStatus(error.message, 'bad');
      }} finally {{
        addSubmit.disabled = false;
      }}
    }});

    document.getElementById('live-refresh').addEventListener('click', () => refreshHosts('Force refreshing host list...').catch(error => setStatus(error.message, 'bad')));

    document.getElementById('export-now').addEventListener('click', async () => {{
      try {{
        setStatus('Forcing immediate export...');
        await api('/dnsmasq/export_now', {{ method: 'POST', csrf: true }});
        setStatus(`Forced export completed at ${{humanTimestamp()}}.`, 'good', true);
      }} catch (error) {{
        setStatus(error.message, 'bad');
      }}
    }});

    statusCloseEl.addEventListener('click', hideStatus);

    hostsBody.addEventListener('click', async (event) => {{
      const button = event.target.closest('button[data-action]');
      if (!button) return;
      const action = button.dataset.action;
      const ip = button.dataset.ip;
      const host = button.dataset.host;
      try {{
        if (action === 'delete-host') {{
          setStatus(`Deleting host ${{host}} from ${{ip}}...`);
          const data = await api(`/dnsmasq/${{encodeURIComponent(ip)}}/${{encodeURIComponent(host)}}`, {{
            method: 'DELETE',
            csrf: true
          }});
          setStatus(`Removed ${{data.removed_host_count}} host entry from ${{ip}} at ${{humanTimestamp()}}.`, 'good', true);
        }} else if (action === 'delete-ip') {{
          setStatus(`Deleting all hosts for ${{ip}}...`);
          const data = await api(`/dnsmasq/${{encodeURIComponent(ip)}}`, {{
            method: 'DELETE',
            csrf: true
          }});
          setStatus(`Removed ${{data.removed_host_count}} host entries for ${{ip}} at ${{humanTimestamp()}}.`, 'good', true);
        }}
        await refreshHosts();
      }} catch (error) {{
        setStatus(error.message, 'bad');
      }}
    }});

    updateClock();
    setInterval(updateClock, 1000);

    refreshHosts().catch(error => setStatus(error.message, 'bad'));
    refreshTimer = setInterval(() => {{
      refreshHosts('Auto refreshing host list...').catch(error => setStatus(error.message, 'bad'));
    }}, 5000);
  </script>
</body>
</html>"#
    )
}

fn maybe_log_no_pending(store: &mut Store, db_generation: i64, file_generation: i64) {
    const NO_PENDING_LOG_SUPPRESSION: Duration = Duration::from_secs(60 * 60 * 24 * 2);

    let should_log = store
        .last_no_pending_log_at
        .is_none_or(|last| last.elapsed() >= NO_PENDING_LOG_SUPPRESSION);
    if should_log {
        debug!(
            db_generation,
            file_generation, "no pending sqlite-backed changes; skipping flush"
        );
        store.last_no_pending_log_at = Some(Instant::now());
    }
}

fn reset_no_pending_log_suppression(store: &mut Store) {
    store.last_no_pending_log_at = None;
}
