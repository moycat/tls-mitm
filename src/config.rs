//! TOML configuration and validation for the proxy, DNS relay and PCAP stream.

use crate::cert::normalize_dns_name;
use crate::dns::{points_to_self, DnsConfig};
use crate::proxy::Route;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFile {
    pub domain: String,
    pub upstream: String,
    pub upstream_port: Option<u16>,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFile {
    pub listen: Option<String>,
    pub map_port: Option<u16>,
    pub output: Option<PathBuf>,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub proxy: ProxySettings,
    pub routes: Vec<Route>,
    pub dns: Option<DnsConfig>,
    pub capture: Option<CaptureSettings>,
}

#[derive(Debug)]
pub struct ProxySettings {
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub listen: Vec<SocketAddr>,
    pub upstream_port: Option<u16>,
    pub resolver: SocketAddr,
    pub upstream_ca: Option<PathBuf>,
    pub default_host: Option<String>,
}

#[derive(Debug)]
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
    let path =
        fs::canonicalize(path).with_context(|| format!("find config file {}", path.display()))?;
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let file: FileConfig = toml::from_str(&contents)
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
        let proxy = ProxySettings {
            ca_cert: relative_to(base, proxy.ca_cert),
            ca_key: relative_to(base, proxy.ca_key),
            listen,
            upstream_port: proxy.upstream_port,
            resolver,
            upstream_ca: proxy.upstream_ca.map(|path| relative_to(base, path)),
            default_host,
        };

        let mut seen_routes = HashSet::new();
        let mut routes = Vec::with_capacity(file.routes.len());
        for (index, item) in file.routes.into_iter().enumerate() {
            let mut route = Route::parse(&format!("{}={}", item.domain, item.upstream))
                .with_context(|| format!("invalid route {}", index + 1))?;
            if !seen_routes.insert(route.pattern.clone()) {
                bail!("duplicate route domain: {}", route.pattern);
            }
            if item.upstream_port == Some(0) {
                bail!("route {}: upstream_port must be nonzero", index + 1);
            }
            if route.port.is_some() && item.upstream_port.is_some() {
                bail!(
                    "route {}: specify the upstream port in upstream or upstream_port, not both",
                    index + 1
                );
            }
            route.port = route.port.or(item.upstream_port);
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
    let domains = file
        .domains
        .iter()
        .map(|name| normalize_dns_pattern(name).context("invalid dns.domains entry"))
        .collect::<Result<Vec<_>>>()?;
    if !file.all && domains.is_empty() {
        bail!("[dns] requires all = true or at least one domain");
    }
    let mut seen = HashSet::new();
    let domains = domains
        .into_iter()
        .filter(|domain| seen.insert(domain.clone()))
        .collect();
    Ok(DnsConfig {
        bind,
        upstream: resolver,
        answer_v4,
        answer_v6,
        hijack_all: file.all,
        domains,
    })
}

fn normalize_dns_pattern(pattern: &str) -> Result<String> {
    if pattern == "*" {
        return Ok(pattern.to_owned());
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return Ok(format!("*.{}", normalize_dns_name(suffix)?));
    }
    normalize_dns_name(pattern)
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
        assert!(config.routes.is_empty());
        assert!(config.dns.is_none());
        assert!(config.capture.is_none());
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
upstream = 'tcp://127.0.0.1'
upstream_port = 8080

[[route]]
domain = 'api.example.com'
upstream = 'tls://backend.example.com'
upstream_port = 443
verify_name = 'BACKEND.example.com.'

[[route]]
domain = 'insecure.example.com'
upstream = 'tls://192.0.2.20:9443'
verify = false

[[route]]
domain = 'fallback.example.com'
upstream = 'backend.example.com'

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
        assert_eq!(config.routes[0].pattern, "*.example.com");
        assert!(!config.routes[0].tls);
        assert_eq!(config.routes[0].port, Some(8080));
        assert!(config.routes[0].verify);
        assert_eq!(config.routes[1].port, Some(443));
        assert!(config.routes[1].verify);
        assert_eq!(
            config.routes[1].verify_name.as_deref(),
            Some("backend.example.com")
        );
        assert_eq!(config.routes[2].port, Some(9443));
        assert!(!config.routes[2].verify);
        assert_eq!(config.routes[3].port, None);
        assert!(config.routes[3].tls);
        assert!(config.routes[3].verify);
        let dns = config.dns.unwrap();
        assert_eq!(dns.domains, ["example.com"]);
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
             domains = ['*.EXAMPLE.com.', '*.example.com', 'example.com', '*']\n",
        )
        .unwrap();
        assert_eq!(
            config.dns.unwrap().domains,
            ["*.example.com", "example.com", "*"]
        );
    }

    #[test]
    fn rejects_malformed_dns_wildcard_patterns() {
        let base = "[proxy]\nca_cert = 'ca.pem'\nca_key = 'key.pem'\n\
                    [dns]\nlisten = '127.0.0.1:5300'\nip = '127.0.0.1'\n";
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
            let error = load_text(&format!("{base}domains = ['{bad}']\n")).unwrap_err();
            assert!(
                format!("{error:#}").contains("invalid dns.domains entry"),
                "{bad}: {error:#}"
            );
        }
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
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1:443'\nupstream_port = 9443\n",
            "\n[[route]]\ndomain = 'example.com'\nupstream = 'tls://127.0.0.1'\nupstream_port = 0\n",
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
