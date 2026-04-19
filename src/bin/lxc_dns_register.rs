use std::{
    collections::BTreeSet,
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const TTL_SECONDS: u64 = 180;
const REPLACE_MODE_VALUES: &str = "both, host, ip, none";

#[derive(Debug)]
struct Args {
    lxc_path: PathBuf,
    suffix: String,
    mask: Cidr,
    agent: AgentTarget,
    user: Option<BasicAuth>,
    replace_mode: ReplaceMode,
}

#[derive(Debug, Clone)]
struct BasicAuth {
    username: String,
    password: String,
}

#[derive(Debug, Clone)]
struct AgentTarget {
    authority: String,
    socket_addr: SocketAddr,
    path: String,
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

#[derive(Serialize)]
struct AddHostRequest<'a> {
    ip: IpAddr,
    host: &'a str,
    replace_mode: ReplaceMode,
    ttl: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplaceMode {
    Both,
    Host,
    Ip,
    None,
}

impl FromStr for ReplaceMode {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "both" => Ok(Self::Both),
            "host" => Ok(Self::Host),
            "ip" => Ok(Self::Ip),
            "none" => Ok(Self::None),
            _ => bail!("invalid replace mode `{raw}`; expected one of: {REPLACE_MODE_VALUES}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let args = Args::parse()?;

    let output = Command::new(&args.lxc_path)
        .args(["ls", "--format", "json"])
        .output()
        .await
        .with_context(|| format!("failed to execute {}", args.lxc_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{} ls --format json failed with status {}: {}",
            args.lxc_path.display(),
            output.status,
            stderr.trim()
        );
    }

    let instances: Value = serde_json::from_slice(&output.stdout)
        .context("failed to parse lxc ls --format json output")?;
    let entries = instances
        .as_array()
        .ok_or_else(|| anyhow!("expected lxc ls JSON output to be an array"))?;

    let mut attempted = 0usize;
    let mut registered = 0usize;

    for instance in entries {
        let Some(name) = instance.get("name").and_then(Value::as_str) else {
            warn!("skipping lxc instance without a name");
            continue;
        };

        if !is_running(instance) {
            continue;
        }

        let ips = extract_matching_ips(instance, args.mask);
        if ips.is_empty() {
            continue;
        }

        let host = format_host(name, &args.suffix);
        for ip in ips {
            attempted += 1;
            register_host(
                &args.agent,
                args.user.as_ref(),
                ip,
                &host,
                args.replace_mode,
            )
            .await?;
            registered += 1;
            info!(instance = name, %ip, host = %host, "registered instance ip");
        }
    }

    info!(
        attempted,
        registered,
        ttl_seconds = TTL_SECONDS,
        ?args.replace_mode,
        "registration run completed"
    );
    Ok(())
}

impl Args {
    fn parse() -> Result<Self> {
        let mut lxc_path = None;
        let mut suffix = None;
        let mut mask = None;
        let mut agent = None;
        let mut user = None;
        let mut replace_mode = ReplaceMode::Both;

        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = match flag.as_str() {
                "--lxc-path" | "--suffix" | "--mask" | "--agent" | "--user" | "--replace-mode" => {
                    Some(
                        args.next()
                            .ok_or_else(|| anyhow!("missing value for {flag}"))?,
                    )
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => bail!("unknown argument `{flag}`"),
            };

            match flag.as_str() {
                "--lxc-path" => lxc_path = Some(PathBuf::from(value.as_deref().unwrap())),
                "--suffix" => suffix = Some(normalize_suffix(value.as_deref().unwrap())?),
                "--mask" => mask = Some(Cidr::from_str(value.as_deref().unwrap())?),
                "--agent" => agent = Some(AgentTarget::parse(value.as_deref().unwrap())?),
                "--user" => user = Some(parse_basic_auth(value.as_deref().unwrap())?),
                "--replace-mode" => {
                    replace_mode = ReplaceMode::from_str(value.as_deref().unwrap())?
                }
                _ => unreachable!(),
            }
        }

        Ok(Self {
            lxc_path: lxc_path.ok_or_else(|| anyhow!("missing required --lxc-path"))?,
            suffix: suffix.ok_or_else(|| anyhow!("missing required --suffix"))?,
            mask: mask.ok_or_else(|| anyhow!("missing required --mask"))?,
            agent: agent.ok_or_else(|| anyhow!("missing required --agent"))?,
            user,
            replace_mode,
        })
    }
}

impl AgentTarget {
    fn parse(raw: &str) -> Result<Self> {
        if raw.starts_with("https://") {
            bail!("https agents are not supported; use http://host:port or host:port");
        }

        let trimmed = raw.strip_prefix("http://").unwrap_or(raw);
        let (authority, base_path) = match trimmed.split_once('/') {
            Some((authority, rest)) => (authority, format!("/{}", rest.trim_matches('/'))),
            None => (trimmed, String::new()),
        };

        let socket_addr: SocketAddr = authority
            .parse()
            .with_context(|| format!("invalid agent socket address `{authority}`"))?;

        let path = if base_path.is_empty() {
            "/dnsmasq/add_host".to_string()
        } else {
            format!("{}/dnsmasq/add_host", base_path)
        };

        Ok(Self {
            authority: authority.to_string(),
            socket_addr,
            path,
        })
    }
}

impl FromStr for Cidr {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (network_raw, prefix_raw) = raw
            .split_once('/')
            .ok_or_else(|| anyhow!("invalid mask `{raw}`; expected CIDR like 192.168.0.0/24"))?;
        let network: IpAddr = network_raw
            .parse()
            .with_context(|| format!("invalid IP in mask `{raw}`"))?;
        let prefix_len: u8 = prefix_raw
            .parse()
            .with_context(|| format!("invalid prefix length in mask `{raw}`"))?;

        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            bail!("prefix length {prefix_len} out of range for `{raw}`");
        }

        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl Cidr {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("lxc_dns_register=info,info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn print_usage() {
    println!(
        "Usage: lxc_dns_register --lxc-path /path/to/lxc --suffix titan --mask 192.168.0.0/24 --agent 192.168.33.22:8000 [--user username:password] [--replace-mode both|host|ip|none]"
    );
}

fn parse_basic_auth(raw: &str) -> Result<BasicAuth> {
    let Some((username, password)) = raw.split_once(':') else {
        bail!("--user must be username:password");
    };
    Ok(BasicAuth {
        username: username.to_string(),
        password: password.to_string(),
    })
}

fn normalize_suffix(raw: &str) -> Result<String> {
    let suffix = raw.trim().trim_matches('.').to_ascii_lowercase();
    if suffix.is_empty() {
        bail!("--suffix must not be empty");
    }
    Ok(suffix)
}

fn format_host(instance_name: &str, suffix: &str) -> String {
    format!(
        "{}.{}",
        instance_name.trim().trim_matches('.').to_ascii_lowercase(),
        suffix
    )
}

fn is_running(instance: &Value) -> bool {
    instance
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| instance.pointer("/state/status").and_then(Value::as_str))
        .map(|status| status.eq_ignore_ascii_case("running"))
        .unwrap_or(false)
}

fn extract_matching_ips(instance: &Value, mask: Cidr) -> Vec<IpAddr> {
    let mut ips = BTreeSet::new();
    collect_matching_ips(instance.pointer("/state/network"), mask, &mut ips);
    collect_matching_ips(instance.get("state"), mask, &mut ips);
    ips.into_iter().collect()
}

fn collect_matching_ips(value: Option<&Value>, mask: Cidr, ips: &mut BTreeSet<IpAddr>) {
    let Some(value) = value else {
        return;
    };

    match value {
        Value::Object(map) => {
            if let Some(address) = map.get("address").and_then(Value::as_str)
                && let Ok(ip) = address.parse::<IpAddr>()
                && mask.contains(ip)
            {
                ips.insert(ip);
            }

            for child in map.values() {
                collect_matching_ips(Some(child), mask, ips);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_matching_ips(Some(item), mask, ips);
            }
        }
        _ => {}
    }
}

async fn register_host(
    agent: &AgentTarget,
    user: Option<&BasicAuth>,
    ip: IpAddr,
    host: &str,
    replace_mode: ReplaceMode,
) -> Result<()> {
    let payload = AddHostRequest {
        ip,
        host,
        replace_mode,
        ttl: TTL_SECONDS,
    };
    let body = serde_json::to_vec(&payload).context("failed to encode add_host request")?;
    let auth_header = user.map(|user| {
        let raw = format!("{}:{}", user.username, user.password);
        format!("Authorization: Basic {}\r\n", STANDARD.encode(raw))
    });

    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        agent.path,
        agent.authority,
        body.len()
    );
    if let Some(auth_header) = auth_header {
        request.push_str(&auth_header);
    }
    request.push_str("\r\n");

    let mut stream = TcpStream::connect(agent.socket_addr)
        .await
        .with_context(|| format!("failed to connect to agent {}", agent.socket_addr))?;
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write request headers")?;
    stream
        .write_all(&body)
        .await
        .context("failed to write request body")?;
    stream.flush().await.context("failed to flush request")?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("failed to read agent response")?;
    let response_text = String::from_utf8_lossy(&response);
    let status_line = response_text.lines().next().unwrap_or_default();

    if !(status_line.starts_with("HTTP/1.1 2") || status_line.starts_with("HTTP/1.0 2")) {
        bail!(
            "agent registration failed for {} {}: {}",
            ip,
            host,
            response_text.trim()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_contains_ipv4() {
        let cidr = Cidr::from_str("192.168.0.0/24").unwrap();
        assert!(cidr.contains(IpAddr::from_str("192.168.0.9").unwrap()));
        assert!(!cidr.contains(IpAddr::from_str("192.168.1.9").unwrap()));
    }

    #[test]
    fn extracts_matching_ips_from_lxc_shape() {
        let instance = serde_json::json!({
            "name": "web-1",
            "status": "Running",
            "state": {
                "network": {
                    "eth0": {
                        "addresses": [
                            {"family": "inet", "address": "192.168.0.21"},
                            {"family": "inet6", "address": "fe80::1"}
                        ]
                    }
                }
            }
        });

        let ips = extract_matching_ips(&instance, Cidr::from_str("192.168.0.0/24").unwrap());
        assert_eq!(ips, vec![IpAddr::from_str("192.168.0.21").unwrap()]);
    }

    #[test]
    fn formats_host_from_name_and_suffix() {
        assert_eq!(format_host("Web-1", "titan"), "web-1.titan");
    }
}
