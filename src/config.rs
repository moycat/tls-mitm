//! TOML configuration and validation for the proxy, DNS relay and PCAP stream.

use crate::dns::{points_to_self, DnsConfig};
use crate::domain::{normalize_dns_name, DomainPattern};
use crate::proxy::Route;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub proxy: ProxyFile,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteFile>,
    pub dns: Option<DnsFile>,
    pub capture: Option<CaptureFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyFile {
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,
    pub upstream_port: Option<u16>,
    #[serde(default = "default_resolver")]
    pub resolver: String,
    pub upstream_ca: Option<PathBuf>,
    pub default_host: Option<String>,
    #[serde(default)]
    pub exclude_domains: Vec<String>,
    #[serde(default)]
    pub hold_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFile {
    pub domain: String,
    pub upstream: String,
    #[serde(default = "default_route_verify")]
    pub verify: bool,
    pub verify_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsFile {
    pub listen: Option<String>,
    pub ip: Option<String>,
    pub ip6: Option<String>,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub exclude_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFile {
    pub listen: Option<String>,
    pub map_port: Option<u16>,
    pub output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub proxy: ProxySettings,
    pub routes: Vec<Route>,
    pub dns: Option<DnsConfig>,
    pub capture: Option<CaptureSettings>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySettings {
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub listen: Vec<SocketAddr>,
    pub upstream_port: Option<u16>,
    pub resolver: SocketAddr,
    pub upstream_ca: Option<PathBuf>,
    pub default_host: Option<String>,
    pub exclude_domains: Vec<DomainPattern>,
    pub hold_domains: Vec<DomainPattern>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureSettings {
    pub listen: Option<SocketAddr>,
    pub map_port: Option<u16>,
    pub output: Option<PathBuf>,
}

fn default_listen() -> Vec<String> {
    vec!["127.0.0.1:8443".to_owned()]
}

fn default_resolver() -> String {
    "1.1.1.1:53".to_owned()
}

fn default_route_verify() -> bool {
    true
}

/// Read and validate a TOML file. Relative certificate paths are rooted at
/// the config file's directory, regardless of the process working directory.
pub fn load(path: &Path) -> Result<RuntimeConfig> {
    load_snapshot(path).map(|(config, _)| config)
}

/// Read and validate a TOML file, returning the exact bytes used to build the
/// runtime configuration. This lets reload callers verify that the file did
/// not change while a candidate configuration was being prepared.
pub fn load_snapshot(path: &Path) -> Result<(RuntimeConfig, Vec<u8>)> {
    let path = canonical_config_path(path)?;
    let contents =
        fs::read(&path).with_context(|| format!("read config file {}", path.display()))?;
    let config = parse_contents(&path, &contents)?;
    Ok((config, contents))
}

/// Parse and validate exact TOML bytes using the canonical config file's
/// directory as the base for relative paths.
pub fn load_contents(path: &Path, contents: &[u8]) -> Result<RuntimeConfig> {
    let path = config_path_for_contents(path)?;
    parse_contents(&path, contents)
}

fn canonical_config_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("find config file {}", path.display()))
}

fn config_path_for_contents(path: &Path) -> Result<PathBuf> {
    if let Ok(path) = fs::canonicalize(path) {
        return Ok(path);
    }
    let file_name = path
        .file_name()
        .context("config file path has no file name")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = match parent {
        Some(parent) => fs::canonicalize(parent)
            .with_context(|| format!("find config directory {}", parent.display()))?,
        None => std::env::current_dir().context("read current directory")?,
    };
    Ok(parent.join(file_name))
}

fn parse_contents(path: &Path, contents: &[u8]) -> Result<RuntimeConfig> {
    let contents = std::str::from_utf8(contents)
        .with_context(|| format!("decode config file {} as UTF-8", path.display()))?;
    let file: FileConfig = toml::from_str(contents)
        .with_context(|| format!("parse config file {}", path.display()))?;
    let base = path
        .parent()
        .ok_or_else(|| anyhow!("config file has no parent directory"))?;
    RuntimeConfig::from_file(file, base)
        .with_context(|| format!("validate config file {}", path.display()))
}

impl RuntimeConfig {
    fn from_file(file: FileConfig, base: &Path) -> Result<Self> {
        let proxy = file.proxy;
        if proxy.ca_cert.as_os_str().is_empty() || proxy.ca_key.as_os_str().is_empty() {
            bail!("proxy.ca_cert and proxy.ca_key must be nonempty paths");
        }
        if proxy
            .upstream_ca
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            bail!("proxy.upstream_ca must be a nonempty path");
        }
        if proxy.listen.is_empty() {
            bail!("proxy.listen must contain at least one address");
        }
        let listen: Vec<SocketAddr> = proxy
            .listen
            .iter()
            .map(|value| parse_socket_addr(value, "proxy.listen"))
            .collect::<Result<_>>()?;
        if listen.iter().copied().collect::<HashSet<_>>().len() != listen.len() {
            bail!("proxy.listen contains duplicate addresses");
        }
        if proxy.upstream_port == Some(0) {
            bail!("proxy.upstream_port must be nonzero");
        }
        if proxy.upstream_port.is_none() && listen.iter().any(|address| address.port() == 0) {
            bail!("proxy.upstream_port is required when a proxy listener uses port 0");
        }
        let resolver = parse_socket_addr(&proxy.resolver, "proxy.resolver")?;
        if resolver.port() == 0 {
            bail!("proxy.resolver port must be nonzero");
        }
        let default_host = proxy
            .default_host
            .as_deref()
            .map(|name| normalize_dns_name(name).context("invalid proxy.default_host"))
            .transpose()?;
        let exclude_domains =
            parse_domain_patterns(&proxy.exclude_domains, "proxy.exclude_domains")?;
        let hold_domains = parse_domain_patterns(&proxy.hold_domains, "proxy.hold_domains")?;
        let proxy = ProxySettings {
            ca_cert: relative_to(base, proxy.ca_cert),
            ca_key: relative_to(base, proxy.ca_key),
            listen,
            upstream_port: proxy.upstream_port,
            resolver,
            upstream_ca: proxy.upstream_ca.map(|path| relative_to(base, path)),
            default_host,
            exclude_domains,
            hold_domains,
        };

        let mut seen_routes = HashSet::new();
        let mut routes = Vec::with_capacity(file.routes.len());
        for (index, item) in file.routes.into_iter().enumerate() {
            let mut route = Route::parse(&format!("{}={}", item.domain, item.upstream))
                .with_context(|| format!("invalid route {}", index + 1))?;
            if !seen_routes.insert(route.pattern.clone()) {
                bail!("duplicate route domain: {}", route.pattern);
            }
            if !route.tls && !item.verify {
                bail!("route {}: verify requires a TLS upstream", index + 1);
            }
            if !item.verify && item.verify_name.is_some() {
                bail!("route {}: verify_name requires verify = true", index + 1);
            }
            route.verify = item.verify;
            if let Some(name) = item.verify_name {
                if !route.tls {
                    bail!("route {}: verify_name requires a TLS upstream", index + 1);
                }
                route.verify_name = Some(
                    normalize_dns_name(&name)
                        .with_context(|| format!("invalid route {} verify_name", index + 1))?,
                );
            }
            routes.push(route);
        }

        let mut proxy_domain_groups = HashMap::new();
        register_domain_group(
            &mut proxy_domain_groups,
            "proxy.hold_domains",
            proxy.hold_domains.iter(),
        )?;
        register_domain_group(
            &mut proxy_domain_groups,
            "proxy.exclude_domains",
            proxy.exclude_domains.iter(),
        )?;
        register_domain_group(
            &mut proxy_domain_groups,
            "route.domain",
            routes.iter().map(|route| &route.pattern),
        )?;

        let dns = file
            .dns
            .map(|item| dns_config(item, resolver))
            .transpose()?;
        let capture = file
            .capture
            .map(|item| capture_config(item, base))
            .transpose()?;

        Ok(Self {
            proxy,
            routes,
            dns,
            capture,
        })
    }
}

fn dns_config(file: DnsFile, resolver: SocketAddr) -> Result<DnsConfig> {
    let listen = file
        .listen
        .context("dns.listen is required when [dns] is present")?;
    let bind = parse_socket_addr(&listen, "dns.listen")?;
    if bind.port() == 0 {
        bail!("dns.listen port must be nonzero so TCP and UDP share one port");
    }
    if points_to_self(bind, resolver) {
        bail!("proxy.resolver must not point to this tool's DNS listener");
    }
    let answer_v4 = file
        .ip
        .as_deref()
        .map(|value| value.parse::<Ipv4Addr>().context("invalid dns.ip"))
        .transpose()?;
    let answer_v6 = file
        .ip6
        .as_deref()
        .map(|value| value.parse::<Ipv6Addr>().context("invalid dns.ip6"))
        .transpose()?;
    if answer_v4.is_none() && answer_v6.is_none() {
        bail!("[dns] requires ip or ip6");
    }
    let domains = parse_domain_patterns(&file.domains, "dns.domains")?;
    let exclude_domains = parse_domain_patterns(&file.exclude_domains, "dns.exclude_domains")?;
    let mut dns_domain_groups = HashMap::new();
    register_domain_group(&mut dns_domain_groups, "dns.domains", domains.iter())?;
    register_domain_group(
        &mut dns_domain_groups,
        "dns.exclude_domains",
        exclude_domains.iter(),
    )?;
    if !file.all && domains.is_empty() {
        bail!("[dns] requires all = true or at least one domain");
    }
    Ok(DnsConfig {
        bind,
        upstream: resolver,
        answer_v4,
        answer_v6,
        hijack_all: file.all,
        domains,
        exclude_domains,
    })
}

fn parse_domain_patterns(values: &[String], field: &str) -> Result<Vec<DomainPattern>> {
    let patterns = values
        .iter()
        .map(|name| DomainPattern::parse(name).with_context(|| format!("invalid {field} entry")))
        .collect::<Result<Vec<_>>>()?;
    let mut seen = HashSet::new();
    Ok(patterns
        .into_iter()
        .filter(|pattern| seen.insert(pattern.clone()))
        .collect())
}

fn register_domain_group<'a>(
    seen: &mut HashMap<DomainPattern, &'static str>,
    group: &'static str,
    patterns: impl IntoIterator<Item = &'a DomainPattern>,
) -> Result<()> {
    for pattern in patterns {
        if let Some(previous) = seen.insert(pattern.clone(), group) {
            if previous != group {
                bail!("domain pattern {pattern} appears in both {previous} and {group}");
            }
        }
    }
    Ok(())
}

fn capture_config(file: CaptureFile, base: &Path) -> Result<CaptureSettings> {
    if file.map_port == Some(0) {
        bail!("capture.map_port must be nonzero");
    }
    if file
        .output
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        bail!("capture.output must be a nonempty path");
    }
    if file.listen.is_none() && file.output.is_none() {
        bail!("[capture] requires listen or output");
    }
    Ok(CaptureSettings {
        listen: file
            .listen
            .as_deref()
            .map(|value| parse_socket_addr(value, "capture.listen"))
            .transpose()?,
        map_port: file.map_port,
        output: file.output.map(|path| relative_to(base, path)),
    })
}

fn parse_socket_addr(value: &str, field: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid {field} address: {value}"))
}

fn relative_to(base: &Path, path: PathBuf) -> PathBuf {
    base.join(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_text(text: &str) -> Result<RuntimeConfig> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("config.toml");
        fs::write(&file, text)?;
        load(&file)
    }

    #[test]
    fn bundled_example_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/config.toml");
        let config = load(&path).unwrap();
        assert!(!config.proxy.listen.is_empty());
        assert!(config.proxy.ca_cert.is_file());
        assert!(config.proxy.ca_key.is_file());
    }

    #[test]
    fn defaults_and_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        fs::write(
            &file,
            "[proxy]\nca_cert = 'certs/ca.pem'\nca_key = 'certs/key.pem'\n",
        )
        .unwrap();
        let config = load(&file).unwrap();
        let base = dir.path().canonicalize().unwrap();
        assert_eq!(config.proxy.ca_cert, base.join("certs/ca.pem"));
        assert_eq!(config.proxy.ca_key, base.join("certs/key.pem"));
        assert_eq!(config.proxy.listen, ["127.0.0.1:8443".parse().unwrap()]);
        assert_eq!(config.proxy.resolver, "1.1.1.1:53".parse().unwrap());
        assert!(config.proxy.exclude_domains.is_empty());
        assert!(config.proxy.hold_domains.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.dns.is_none());
        assert!(config.capture.is_none());
    }

    #[test]
    fn snapshot_returns_the_exact_parsed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        let first = b"[proxy]\nca_cert = 'first/ca.pem'\nca_key = 'first/key.pem'\ndefault_host = 'FIRST.example.'\n";
        fs::write(&file, first).unwrap();

        let (config, snapshot) = load_snapshot(&file).unwrap();
        assert_eq!(snapshot, first);
        assert_eq!(config.proxy.default_host.as_deref(), Some("first.example"));

        fs::write(
            &file,
            b"[proxy]\nca_cert = 'second/ca.pem'\nca_key = 'second/key.pem'\ndefault_host = 'SECOND.example.'\n",
        )
        .unwrap();
        let from_snapshot = load_contents(&file, &snapshot).unwrap();
        let from_file = load(&file).unwrap();
        assert_eq!(
            from_snapshot.proxy.default_host.as_deref(),
            Some("first.example")
        );
        assert_eq!(
            from_file.proxy.default_host.as_deref(),
            Some("second.example")
        );
        assert_eq!(
            from_snapshot.proxy.ca_cert,
            dir.path().canonicalize().unwrap().join("first/ca.pem")
        );

        fs::remove_file(&file).unwrap();
        let while_replaced = load_contents(&file, &snapshot).unwrap();
        assert_eq!(
            while_replaced.proxy.default_host.as_deref(),
            Some("first.example")
        );
    }

    #[test]
    fn exact_bytes_report_decode_and_toml_context() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        fs::write(&file, "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n").unwrap();

        let error = load_contents(&file, b"[proxy]\nca_cert = '\xff'\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("decode config file"), "{message}");
        assert!(message.contains("config.toml as UTF-8"), "{message}");

        let error = load_contents(&file, b"[proxy").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("parse config file"), "{message}");
        assert!(message.contains("config.toml"), "{message}");
    }

    #[test]
    fn parses_routes_dns_and_capture() {
        let config = load_text(
            r#"[proxy]
ca_cert = 'ca.pem'
ca_key = 'key.pem'
listen = ['127.0.0.1:0']
upstream_port = 443
upstream_ca = 'upstream.pem'
default_host = 'DEFAULT.Example.'

[[route]]
domain = '*.EXAMPLE.com.'
upstream = 'tcp://127.0.0.1:8080'

[[route]]
domain = 'api.example.com'
upstream = 'tls://backend.example.com:443'
verify_name = 'BACKEND.example.com.'

[[route]]
domain = 'insecure.example.com'
upstream = 'tls://192.0.2.20:9443'
verify = false

[[route]]
domain = 'fallback.example.com'
upstream = 'tls://backend.example.com:8443'

[dns]
listen = '127.0.0.1:5300'
ip = '192.0.2.10'
all = false
domains = ['EXAMPLE.com.', 'example.com']

[capture]
listen = '127.0.0.1:57012'
map_port = 80
output = 'captures/current.pcap'
"#,
        )
        .unwrap();
        assert_eq!(
            config.proxy.default_host.as_deref(),
            Some("default.example")
        );
        assert!(config.proxy.upstream_ca.unwrap().is_absolute());
        assert_eq!(config.routes[0].pattern.as_str(), "*.example.com");
        assert!(!config.routes[0].tls);
        assert_eq!(config.routes[0].port, 8080);
        assert!(config.routes[0].verify);
        assert_eq!(config.routes[1].port, 443);
        assert!(config.routes[1].verify);
        assert_eq!(
            config.routes[1].verify_name.as_deref(),
            Some("backend.example.com")
        );
        assert_eq!(config.routes[2].port, 9443);
        assert!(!config.routes[2].verify);
        assert_eq!(config.routes[3].port, 8443);
        assert!(config.routes[3].tls);
        assert!(config.routes[3].verify);
        let dns = config.dns.unwrap();
        assert_eq!(
            dns.domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["example.com"]
        );
        assert!(dns.exclude_domains.is_empty());
        assert_eq!(dns.answer_v4, Some("192.0.2.10".parse().unwrap()));
        let capture = config.capture.unwrap();
        assert_eq!(capture.listen, Some("127.0.0.1:57012".parse().unwrap()));
        assert_eq!(capture.map_port, Some(80));
        assert!(capture.output.unwrap().is_absolute());
    }

    #[test]
    fn capture_output_only_resolves_relative_to_config() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        fs::write(
            &file,
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\n[capture]\noutput = 'capture.fifo'\n",
        )
        .unwrap();
        let config = load(&file).unwrap();
        let capture = config.capture.unwrap();
        assert_eq!(capture.listen, None);
        assert_eq!(capture.map_port, None);
        assert_eq!(
            capture.output,
            Some(dir.path().canonicalize().unwrap().join("capture.fifo"))
        );
    }

    #[test]
    fn parses_dns_wildcard_patterns() {
        let config = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\n\
             all = true\n\
             domains = ['*.EXAMPLE.com.', '*.example.com', 'example.com', '*']\n\
             exclude_domains = ['EXCLUDED.example.', 'excluded.example', '*.SKIP.example.']\n",
        )
        .unwrap();
        let dns = config.dns.unwrap();
        assert_eq!(
            dns.domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["*.example.com", "example.com", "*"]
        );
        assert_eq!(
            dns.exclude_domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["excluded.example", "*.skip.example"]
        );
    }

    #[test]
    fn parses_and_deduplicates_proxy_exclude_domains() {
        let config = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             exclude_domains = ['EXAMPLE.com.', 'example.com', '*.SKIP.example.', '*.skip.example', '*']\n",
        )
        .unwrap();
        assert_eq!(
            config
                .proxy
                .exclude_domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["example.com", "*.skip.example", "*"]
        );
    }

    #[test]
    fn parses_and_deduplicates_proxy_hold_domains() {
        let config = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             hold_domains = ['EXAMPLE.com.', 'example.com', '*.SKIP.example.', '*.skip.example', '*']\n",
        )
        .unwrap();
        assert_eq!(
            config
                .proxy
                .hold_domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["example.com", "*.skip.example", "*"]
        );
    }

    #[test]
    fn proxy_and_dns_exclude_domains_are_independent() {
        let config = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             exclude_domains = ['tls.example']\n\
             [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\nall = true\n\
             exclude_domains = ['dns.example']\n",
        )
        .unwrap();
        assert_eq!(
            config
                .proxy
                .exclude_domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["tls.example"]
        );
        assert_eq!(
            config
                .dns
                .unwrap()
                .exclude_domains
                .iter()
                .map(DomainPattern::as_str)
                .collect::<Vec<_>>(),
            ["dns.example"]
        );
    }

    #[test]
    fn rejects_duplicate_normalized_route_patterns() {
        let error = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             [[route]]\ndomain = 'EXAMPLE.com.'\nupstream = 'tls://127.0.0.1:443'\n\
             [[route]]\ndomain = 'example.com'\nupstream = 'tcp://127.0.0.1:80'\n",
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("duplicate route domain: example.com"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_normalized_patterns_shared_by_proxy_groups() {
        let cases = [
            (
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                 hold_domains = ['EXAMPLE.com.']\nexclude_domains = ['example.com']\n",
                "proxy.hold_domains and proxy.exclude_domains",
            ),
            (
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                 hold_domains = ['*.EXAMPLE.com.']\n\
                 [[route]]\ndomain = '*.example.com'\nupstream = 'tls://127.0.0.1:443'\n",
                "proxy.hold_domains and route.domain",
            ),
            (
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                 exclude_domains = ['EXAMPLE.com.']\n\
                 [[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1:443'\n",
                "proxy.exclude_domains and route.domain",
            ),
            (
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                 hold_domains = ['*']\n\
                 [[route]]\ndomain = '*'\nupstream = 'tls://127.0.0.1:443'\n",
                "proxy.hold_domains and route.domain",
            ),
        ];

        for (text, groups) in cases {
            let error = load_text(text).unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains("domain pattern") && message.contains(groups),
                "{message}"
            );
        }
    }

    #[test]
    fn rejects_normalized_patterns_shared_by_dns_groups() {
        for (domain, exclusion, normalized) in [
            ("*.EXAMPLE.com.", "*.example.com", "*.example.com"),
            ("*", "*", "*"),
        ] {
            let error = load_text(&format!(
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                 [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\nall = true\n\
                 domains = ['{domain}']\nexclude_domains = ['{exclusion}']\n"
            ))
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!(
                    "domain pattern {normalized} appears in both dns.domains and dns.exclude_domains"
                )),
                "{message}"
            );
        }
    }

    #[test]
    fn allows_overlapping_distinct_patterns_and_proxy_dns_reuse() {
        let config = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             hold_domains = ['example.com']\n\
             exclude_domains = ['*.example.com', 'shared.example']\n\
             [[route]]\ndomain = 'api.example.com'\nupstream = 'tls://127.0.0.1:443'\n\
             [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\nall = true\n\
             domains = ['example.com']\n\
             exclude_domains = ['*.example.com', 'shared.example']\n",
        )
        .unwrap();

        assert_eq!(config.routes[0].pattern.as_str(), "api.example.com");
        assert_eq!(config.proxy.exclude_domains[1].as_str(), "shared.example");
        assert_eq!(
            config.dns.unwrap().exclude_domains[1].as_str(),
            "shared.example"
        );
    }

    #[test]
    fn rejects_malformed_dns_wildcard_patterns() {
        let base = "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                    [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\nall = true\n";
        for bad in [
            "*.",
            "*..example.com",
            "*.*.example.com",
            "*example.com",
            "foo*.example.com",
            "foo.*.example.com",
            "a*b.com",
            "*.bad_name",
        ] {
            for field in ["domains", "exclude_domains"] {
                let error = load_text(&format!("{base}{field} = ['{bad}']\n")).unwrap_err();
                assert!(
                    format!("{error:#}").contains(&format!("invalid dns.{field} entry")),
                    "{field} {bad}: {error:#}"
                );
            }
        }
    }

    #[test]
    fn rejects_malformed_proxy_exclude_domains() {
        for bad in [
            "*.",
            "*..example.com",
            "*.*.example.com",
            "*example.com",
            "foo*.example.com",
            "foo.*.example.com",
            "a*b.com",
            "*.bad_name",
        ] {
            let error = load_text(&format!(
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\nexclude_domains = ['{bad}']\n"
            ))
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("invalid proxy.exclude_domains entry"),
                "{bad}: {error:#}"
            );
        }
    }

    #[test]
    fn rejects_malformed_proxy_hold_domains() {
        for bad in [
            "*.",
            "*..example.com",
            "*.*.example.com",
            "*example.com",
            "foo*.example.com",
            "foo.*.example.com",
            "a*b.com",
            "*.bad_name",
        ] {
            let error = load_text(&format!(
                "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\nhold_domains = ['{bad}']\n"
            ))
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("invalid proxy.hold_domains entry"),
                "{bad}: {error:#}"
            );
        }
    }

    #[test]
    fn exclude_domains_do_not_enable_selective_mode() {
        let error = load_text(
            "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
             [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\n\
             exclude_domains = ['example.com']\n",
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("[dns] requires all = true or at least one domain"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_typos_and_incomplete_sections() {
        let base = "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n";
        for bad in [
            "resovler = '1.1.1.1:53'\n",
            "\n[dns]\nlisten = '127.0.0.1:53'\nip = '127.0.0.1'\n",
            "\n[dns]\nip = '127.0.0.1'\nall = true\n",
            "\n[capture]\nport = 80\n",
            "\n[capture]\n",
            "\n[capture]\nmap_port = 80\n",
            "\n[capture]\nmap_port = 0\noutput = 'capture.pcap'\n",
            "\n[capture]\noutput = ''\n",
            "\n[capture]\nlisten = 'not-an-address'\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tcp://127.0.0.1:80'\nverify_name = 'example.com'\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1:443'\nverfiy_name = 'example.com'\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1'\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1:0'\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1:443'\nverify = false\nverify_name = 'example.com'\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tcp://127.0.0.1:80'\nverify = false\n",
            "\n[dns]\nlisten = '127.0.0.1:53'\nip = '127.0.0.1'\nall = true\nunknwon = true\n",
            "\n[capture]\nlisten = '127.0.0.1:57012'\nporrt = 80\n",
            "\n[capture]\nlisten = '127.0.0.1:57012'\nport = 80\n",
        ] {
            assert!(load_text(&format!("{base}{bad}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn configured_routes_require_ports_and_accept_bracketed_ipv6() {
        let base = "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n";
        for upstream in [
            "tls://backend.example.com",
            "tcp://192.0.2.10",
            "tls://[2001:db8::1]",
        ] {
            let error = load_text(&format!(
                "{base}\n[[route]]\ndomain = 'example.com'\nupstream = '{upstream}'\n"
            ))
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("upstream port is required"),
                "{upstream}: {error:#}"
            );
        }

        for upstream in [
            "tls://backend.example.com:0",
            "tcp://192.0.2.10:0",
            "tls://[2001:db8::1]:0",
        ] {
            let error = load_text(&format!(
                "{base}\n[[route]]\ndomain = 'example.com'\nupstream = '{upstream}'\n"
            ))
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("upstream port must be nonzero"),
                "{upstream}: {error:#}"
            );
        }

        let config = load_text(&format!(
            "{base}\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://[2001:db8::1]:443'\n"
        ))
        .unwrap();
        assert_eq!(config.routes[0].host, "2001:db8::1");
        assert_eq!(config.routes[0].port, 443);
    }

    #[test]
    fn rejects_dns_resolver_loop_and_unusable_ports() {
        let base = "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n";
        assert!(load_text(&format!(
            "{base}resolver = '127.0.0.1:53'\n[dns]\nlisten = '0.0.0.0:53'\nip = '127.0.0.1'\nall = true\n"
        ))
        .is_err());
        assert!(load_text(&format!("{base}listen = ['127.0.0.1:0']\n")).is_err());
        assert!(load_text(&format!("{base}upstream_port = 0\n")).is_err());
        assert!(load_text(&format!(
            "{base}\n[dns]\nlisten = '127.0.0.1:0'\nip = '127.0.0.1'\nall = true\n"
        ))
        .is_err());
    }
}
