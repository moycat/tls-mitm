use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use ring::digest::{Context as DigestContext, SHA256};
use rustls::ClientConfig;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tls_mitm::capture::{start_capture, CaptureHub};
use tls_mitm::cert::CertificateAuthority;
use tls_mitm::config::{load_contents, load_snapshot, RuntimeConfig};
use tls_mitm::dns::{DnsConfigHandle, DnsServer};
use tls_mitm::proxy::{build_upstream_client, Proxy, ProxyConfig, ProxyConfigHandle};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

const CONFIG_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CONFIG_DEBOUNCE: Duration = Duration::from_millis(500);

#[derive(Parser, Debug)]
#[command(version, about = "SNI-based TLS security test proxy")]
struct Args {
    /// TOML configuration file.
    #[arg(long, default_value = "example/config.toml")]
    config: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging()?;
    let config_path = absolute_path(&args.config)?;
    let (settings, config_bytes) = load_snapshot(&config_path)?;
    debug!(
        config = %config_path.display(),
        proxy_listeners = settings.proxy.listen.len(),
        routes = settings.routes.len(),
        dns_enabled = settings.dns.is_some(),
        capture_enabled = settings.capture.is_some(),
        "configuration loaded"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config_path, settings, config_bytes))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .context("read current directory")?
            .join(path)
    };
    fs::canonicalize(&absolute).with_context(|| format!("find config file {}", absolute.display()))
}

fn init_logging() -> Result<()> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) => EnvFilter::try_new(value).context("invalid RUST_LOG filter")?,
        Err(std::env::VarError::NotPresent) => EnvFilter::new("tls_mitm=info"),
        Err(error) => return Err(error).context("read RUST_LOG"),
    };
    let term = std::env::var_os("TERM");
    let no_color = std::env::var_os("NO_COLOR");
    let ansi = ansi_enabled(
        std::io::stderr().is_terminal(),
        term.as_deref(),
        no_color.as_deref(),
    );
    tracing_subscriber::fmt()
        .compact()
        .with_ansi(ansi)
        .with_target(true)
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init()
        .map_err(|error| anyhow!("initialize logging: {error}"))
}

fn ansi_enabled(is_terminal: bool, term: Option<&OsStr>, no_color: Option<&OsStr>) -> bool {
    is_terminal && term != Some(OsStr::new("dumb")) && no_color.is_none_or(|value| value.is_empty())
}

#[derive(Clone)]
struct PreparedMaterials {
    ca: CertificateAuthority,
    upstream_client: Arc<ClientConfig>,
    ca_fingerprint: [u8; 32],
    upstream_trust_fingerprint: [u8; 32],
}

struct ActiveRuntime {
    settings: RuntimeConfig,
    config_bytes: Vec<u8>,
    materials: PreparedMaterials,
    ca_revision: u64,
    upstream_trust_revision: u64,
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfigObservation {
    Contents(Vec<u8>),
    ReadError(String),
}

struct ReloadMonitor {
    pending: ConfigObservation,
    pending_since: Instant,
    last_attempted: Option<ConfigObservation>,
}

impl ReloadMonitor {
    fn new(initial: Vec<u8>) -> Self {
        let initial = ConfigObservation::Contents(initial);
        Self {
            pending: initial.clone(),
            pending_since: Instant::now(),
            last_attempted: Some(initial),
        }
    }

    fn observe(&mut self, observation: ConfigObservation) -> Option<ConfigObservation> {
        if observation != self.pending {
            self.pending = observation;
            self.pending_since = Instant::now();
            return None;
        }
        if self.pending_since.elapsed() < CONFIG_DEBOUNCE
            || self.last_attempted.as_ref() == Some(&self.pending)
        {
            return None;
        }
        self.last_attempted = Some(self.pending.clone());
        Some(self.pending.clone())
    }

    fn retry_pending(&mut self) {
        self.last_attempted = None;
        self.pending_since = Instant::now();
    }
}

enum ReloadOutcome {
    Applied,
    Stale,
}

async fn run(config_path: PathBuf, settings: RuntimeConfig, config_bytes: Vec<u8>) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("could not initialize TLS crypto provider"))?;

    let materials = prepare_materials(&settings)?;
    let capture = start_configured_capture(&settings).await?;

    let mut proxies = Vec::with_capacity(settings.proxy.listen.len());
    let mut proxy_handles = HashMap::with_capacity(settings.proxy.listen.len());
    for &listen in &settings.proxy.listen {
        let proxy = Proxy::bind(make_proxy_config(
            listen,
            &settings,
            &materials,
            capture.clone(),
            0,
            0,
        )?)
        .await?;
        info!(listen = %proxy.local_addr()?, "TLS proxy listening");
        proxy_handles.insert(listen, proxy.config_handle());
        proxies.push(proxy);
    }

    let (dns_server, dns_handle) = match settings.dns.clone() {
        Some(config) => {
            let server = DnsServer::bind(config.clone()).await?;
            info!(listen = %server.local_addr()?, upstream = %config.upstream, "DNS server listening");
            let handle = server.config_handle();
            (Some(server), Some(handle))
        }
        None => (None, None),
    };

    let mut services = FuturesUnordered::new();
    for proxy in proxies {
        services.push(tokio::spawn(proxy.serve()));
    }
    if let Some(server) = dns_server {
        services.push(tokio::spawn(server.serve()));
    }

    let mut active = ActiveRuntime {
        settings,
        config_bytes: config_bytes.clone(),
        materials,
        ca_revision: 0,
        upstream_trust_revision: 0,
        generation: 1,
    };
    let mut monitor = ReloadMonitor::new(config_bytes);
    let mut poll = tokio::time::interval(CONFIG_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        let service = services.next();
        let tick = poll.tick();
        tokio::pin!(service);
        tokio::pin!(tick);
        match futures::future::select(service, tick).await {
            futures::future::Either::Left((joined, _)) => {
                let joined = joined.context("network service set unexpectedly became empty")?;
                let result = joined.context("network service task failed")?;
                return match result {
                    Ok(()) => Err(anyhow!("network service stopped unexpectedly")),
                    Err(error) => Err(error).context("network service failed"),
                };
            }
            futures::future::Either::Right((_, _)) => {}
        }

        let observation = match fs::read(&config_path) {
            Ok(contents) => ConfigObservation::Contents(contents),
            Err(read_error) => ConfigObservation::ReadError(format!(
                "read config file {}: {read_error}",
                config_path.display()
            )),
        };
        let Some(observation) = monitor.observe(observation) else {
            continue;
        };
        let candidate = match observation {
            ConfigObservation::Contents(contents) => contents,
            ConfigObservation::ReadError(read_error) => {
                error!(
                    config = %config_path.display(),
                    error = %read_error,
                    "configuration reload rejected; keeping previous configuration"
                );
                continue;
            }
        };
        if candidate == active.config_bytes {
            continue;
        }

        match reload_configuration(
            &config_path,
            candidate,
            &mut active,
            &proxy_handles,
            dns_handle.as_ref(),
            capture.clone(),
        )
        .await
        {
            Ok(ReloadOutcome::Applied) => info!(
                config = %config_path.display(),
                generation = active.generation,
                "configuration reloaded"
            ),
            Ok(ReloadOutcome::Stale) => monitor.retry_pending(),
            Err(reload_error) => error!(
                config = %config_path.display(),
                error = %format_args!("{reload_error:#}"),
                "configuration reload rejected; keeping previous configuration"
            ),
        }
    }
}

async fn start_configured_capture(settings: &RuntimeConfig) -> Result<Option<Arc<CaptureHub>>> {
    let Some(capture) = &settings.capture else {
        return Ok(None);
    };
    let hub = start_capture(capture.listen, capture.map_port, capture.output.clone()).await?;
    if let Some(listen) = hub.local_addr() {
        info!(%listen, "PCAP stream listening");
    }
    if let Some(output) = &capture.output {
        info!(path = %output.display(), "PCAP file output enabled");
    }
    Ok(Some(hub))
}

fn make_proxy_config(
    listen: SocketAddr,
    settings: &RuntimeConfig,
    materials: &PreparedMaterials,
    capture: Option<Arc<CaptureHub>>,
    ca_revision: u64,
    upstream_trust_revision: u64,
) -> Result<ProxyConfig> {
    let upstream_port = settings.proxy.upstream_port.unwrap_or(listen.port());
    if upstream_port == 0 {
        bail!("proxy.upstream_port is required when a listener uses port 0");
    }
    Ok(ProxyConfig {
        listen,
        default_upstream_port: upstream_port,
        resolver: settings.proxy.resolver,
        ca: materials.ca.clone(),
        routes: settings.routes.clone(),
        hold_domains: settings.proxy.hold_domains.clone(),
        exclude_domains: settings.proxy.exclude_domains.clone(),
        default_host: settings.proxy.default_host.clone(),
        upstream_client: materials.upstream_client.clone(),
        capture,
        ca_revision,
        upstream_trust_revision,
    })
}

async fn reload_configuration(
    config_path: &Path,
    candidate_bytes: Vec<u8>,
    active: &mut ActiveRuntime,
    proxy_handles: &HashMap<SocketAddr, ProxyConfigHandle>,
    dns_handle: Option<&DnsConfigHandle>,
    capture: Option<Arc<CaptureHub>>,
) -> Result<ReloadOutcome> {
    let candidate = load_contents(config_path, &candidate_bytes)?;
    ensure_reloadable_topology(&active.settings, &candidate)?;

    let prepare_candidate = candidate.clone();
    let mut materials = tokio::task::spawn_blocking(move || prepare_materials(&prepare_candidate))
        .await
        .context("configuration preparation task failed")??;

    let ca_changed = materials.ca_fingerprint != active.materials.ca_fingerprint;
    let upstream_trust_changed =
        materials.upstream_trust_fingerprint != active.materials.upstream_trust_fingerprint;
    let ca_revision = if ca_changed {
        active
            .ca_revision
            .checked_add(1)
            .context("CA reload revision overflow")?
    } else {
        materials.ca = active.materials.ca.clone();
        active.ca_revision
    };
    let upstream_trust_revision = if upstream_trust_changed {
        active
            .upstream_trust_revision
            .checked_add(1)
            .context("upstream trust reload revision overflow")?
    } else {
        materials.upstream_client = active.materials.upstream_client.clone();
        active.upstream_trust_revision
    };

    let new_generation = active
        .generation
        .checked_add(1)
        .context("configuration generation overflow")?;
    let mut proxy_updates = Vec::with_capacity(candidate.proxy.listen.len());
    for &listen in &candidate.proxy.listen {
        let handle = proxy_handles
            .get(&listen)
            .with_context(|| format!("missing retained TLS listener {listen}"))?
            .clone();
        let config = make_proxy_config(
            listen,
            &candidate,
            &materials,
            capture.clone(),
            ca_revision,
            upstream_trust_revision,
        )?;
        proxy_updates.push(handle.prepare_replace(config)?);
    }

    let dns_update = match (dns_handle, candidate.dns.clone()) {
        (Some(handle), Some(config)) => Some(handle.prepare_replace(config)?),
        (None, None) => None,
        _ => bail!("DNS listener topology changed during reload"),
    };

    if fs::read(config_path).ok().as_deref() != Some(candidate_bytes.as_slice()) {
        return Ok(ReloadOutcome::Stale);
    }

    if let Some(update) = dns_update {
        update.publish();
    }
    for update in proxy_updates {
        update.publish();
    }

    *active = ActiveRuntime {
        settings: candidate,
        config_bytes: candidate_bytes,
        materials,
        ca_revision,
        upstream_trust_revision,
        generation: new_generation,
    };
    Ok(ReloadOutcome::Applied)
}

fn ensure_reloadable_topology(current: &RuntimeConfig, candidate: &RuntimeConfig) -> Result<()> {
    let current_listeners: HashSet<_> = current.proxy.listen.iter().copied().collect();
    let candidate_listeners: HashSet<_> = candidate.proxy.listen.iter().copied().collect();
    if current_listeners != candidate_listeners {
        bail!("proxy.listen cannot change during reload; restart required");
    }
    match (&current.dns, &candidate.dns) {
        (None, None) => {}
        (Some(current), Some(candidate)) if current.bind == candidate.bind => {}
        _ => bail!("[dns] presence and dns.listen cannot change during reload; restart required"),
    }
    if current.capture != candidate.capture {
        bail!("[capture] cannot change during reload; restart required");
    }
    Ok(())
}

fn prepare_materials(settings: &RuntimeConfig) -> Result<PreparedMaterials> {
    let ca_before = ca_fingerprint(&settings.proxy.ca_cert, &settings.proxy.ca_key)?;
    let ca = CertificateAuthority::new(&settings.proxy.ca_cert, &settings.proxy.ca_key)?;
    let ca_after = ca_fingerprint(&settings.proxy.ca_cert, &settings.proxy.ca_key)?;
    if ca_before != ca_after {
        bail!("CA files changed while preparing configuration");
    }

    let trust_before = upstream_trust_fingerprint(settings.proxy.upstream_ca.as_deref())?;
    let upstream_client = build_upstream_client(settings.proxy.upstream_ca.as_deref())?;
    let trust_after = upstream_trust_fingerprint(settings.proxy.upstream_ca.as_deref())?;
    if trust_before != trust_after {
        bail!("upstream CA file changed while preparing configuration");
    }

    Ok(PreparedMaterials {
        ca,
        upstream_client,
        ca_fingerprint: ca_after,
        upstream_trust_fingerprint: trust_after,
    })
}

fn ca_fingerprint(cert: &Path, key: &Path) -> Result<[u8; 32]> {
    fingerprint_files(b"tls-mitm-ca-v1", &[cert, key])
}

fn upstream_trust_fingerprint(extra_ca: Option<&Path>) -> Result<[u8; 32]> {
    match extra_ca {
        Some(path) => fingerprint_files(b"tls-mitm-upstream-roots-v1+extra", &[path]),
        None => fingerprint_files(b"tls-mitm-upstream-roots-v1", &[]),
    }
}

fn fingerprint_files(domain: &[u8], paths: &[&Path]) -> Result<[u8; 32]> {
    let mut digest = DigestContext::new(&SHA256);
    digest.update(&(domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for path in paths {
        let contents = fs::read(path)
            .with_context(|| format!("read configuration material {}", path.display()))?;
        digest.update(&(contents.len() as u64).to_be_bytes());
        digest.update(&contents);
    }
    let digest = digest.finish();
    let mut result = [0; 32];
    result.copy_from_slice(digest.as_ref());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::RootCertStore;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tls_mitm::config::{CaptureSettings, ProxySettings};
    use tls_mitm::dns::DnsConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    fn runtime_config() -> RuntimeConfig {
        RuntimeConfig {
            proxy: ProxySettings {
                ca_cert: PathBuf::from("ca.pem"),
                ca_key: PathBuf::from("ca.key"),
                listen: vec![
                    "127.0.0.1:443".parse().unwrap(),
                    "127.0.0.1:8443".parse().unwrap(),
                ],
                upstream_port: Some(443),
                resolver: "127.0.0.1:5353".parse().unwrap(),
                upstream_ca: None,
                default_host: None,
                hold_domains: Vec::new(),
                exclude_domains: Vec::new(),
            },
            routes: Vec::new(),
            dns: None,
            capture: None,
        }
    }

    fn dns_config(bind: &str) -> DnsConfig {
        DnsConfig {
            bind: bind.parse().unwrap(),
            upstream: "127.0.0.1:5353".parse().unwrap(),
            answer_v4: Some(Ipv4Addr::LOCALHOST),
            answer_v6: Some(Ipv6Addr::LOCALHOST),
            hijack_all: true,
            domains: Vec::new(),
            exclude_domains: Vec::new(),
        }
    }

    #[test]
    fn ansi_colors_require_a_capable_terminal() {
        assert!(ansi_enabled(true, Some(OsStr::new("xterm-256color")), None));
        assert!(!ansi_enabled(
            false,
            Some(OsStr::new("xterm-256color")),
            None
        ));
        assert!(!ansi_enabled(true, Some(OsStr::new("dumb")), None));
        assert!(!ansi_enabled(
            true,
            Some(OsStr::new("xterm")),
            Some(OsStr::new("1"))
        ));
        assert!(ansi_enabled(
            true,
            Some(OsStr::new("xterm")),
            Some(OsStr::new(""))
        ));
    }

    #[test]
    fn reload_keeps_listener_addresses_and_capture_fixed() {
        let current = runtime_config();

        let mut reordered = current.clone();
        reordered.proxy.listen.reverse();
        ensure_reloadable_topology(&current, &reordered).unwrap();

        let mut changed_proxy = current.clone();
        changed_proxy.proxy.listen[0] = "127.0.0.1:444".parse().unwrap();
        assert!(format!(
            "{:#}",
            ensure_reloadable_topology(&current, &changed_proxy).unwrap_err()
        )
        .contains("proxy.listen cannot change"));

        let mut changed_capture = current.clone();
        changed_capture.capture = Some(CaptureSettings {
            listen: Some("127.0.0.1:57012".parse().unwrap()),
            map_port: None,
            output: None,
        });
        assert!(format!(
            "{:#}",
            ensure_reloadable_topology(&current, &changed_capture).unwrap_err()
        )
        .contains("[capture] cannot change"));
    }

    #[test]
    fn reload_keeps_dns_presence_and_listener_fixed() {
        let mut current = runtime_config();
        let mut candidate = current.clone();
        candidate.dns = Some(dns_config("127.0.0.1:5300"));
        assert!(ensure_reloadable_topology(&current, &candidate).is_err());

        current.dns = Some(dns_config("127.0.0.1:5300"));
        candidate = current.clone();
        candidate.dns.as_mut().unwrap().bind = "127.0.0.1:5301".parse().unwrap();
        assert!(format!(
            "{:#}",
            ensure_reloadable_topology(&current, &candidate).unwrap_err()
        )
        .contains("dns.listen cannot change"));

        candidate = current.clone();
        candidate.dns.as_mut().unwrap().answer_v4 = Some(Ipv4Addr::new(192, 0, 2, 10));
        ensure_reloadable_topology(&current, &candidate).unwrap();
    }

    #[test]
    fn stale_reload_candidate_is_retried_after_debounce() {
        let initial = b"initial".to_vec();
        let candidate = ConfigObservation::Contents(b"candidate".to_vec());
        let mut monitor = ReloadMonitor::new(initial);

        assert!(monitor.observe(candidate.clone()).is_none());
        monitor.pending_since = Instant::now() - CONFIG_DEBOUNCE;
        assert_eq!(monitor.observe(candidate.clone()), Some(candidate.clone()));

        monitor.retry_pending();
        monitor.pending_since = Instant::now() - CONFIG_DEBOUNCE;
        assert_eq!(monitor.observe(candidate.clone()), Some(candidate));
    }

    #[test]
    fn watcher_applies_valid_reload_and_keeps_old_listener_on_errors() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
            let listen = reservation.local_addr()?;
            drop(reservation);

            let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs");
            let temp = tempfile::tempdir()?;
            let path = temp.path().join("config.toml");
            let valid = format!(
                "[proxy]\nca_cert = '{}'\nca_key = '{}'\nlisten = ['{listen}']\n\
                 upstream_port = 443\nresolver = '127.0.0.1:9'\n",
                fixture.join("test.crt.pem").display(),
                fixture.join("test.key.pem").display()
            );
            fs::write(&path, &valid)?;
            let path = fs::canonicalize(path)?;
            let (settings, contents) = load_snapshot(&path)?;
            let task = tokio::spawn(run(path.clone(), settings, contents));

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!task.is_finished(), "runtime failed during startup");
            fs::write(&path, b"[proxy\ninvalid")?;
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            assert!(!task.is_finished(), "invalid reload stopped the runtime");
            TcpStream::connect(listen)
                .await
                .context("original listener stopped after invalid reload")?;

            let changed_port = if listen.port() == u16::MAX {
                listen.port() - 1
            } else {
                listen.port() + 1
            };
            let changed_listen = SocketAddr::new(listen.ip(), changed_port);
            let changed = valid.replace(&listen.to_string(), &changed_listen.to_string());
            fs::write(&path, changed)?;
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            assert!(
                !task.is_finished(),
                "listener-change reload stopped the runtime"
            );
            TcpStream::connect(listen)
                .await
                .context("original listener changed during reload")?;

            let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let upstream_address = upstream.local_addr()?;
            let upstream_task = tokio::spawn(async move {
                let (mut stream, _) = upstream.accept().await?;
                let mut request = [0; 1];
                stream.read_exact(&mut request).await?;
                stream.write_all(b"reloaded").await?;
                Ok::<_, anyhow::Error>(())
            });
            let reloaded = format!(
                "{valid}\n[[route]]\ndomain = 'reload.example'\n\
                 upstream = 'tcp://{upstream_address}'\n"
            );
            fs::write(&path, reloaded)?;
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            assert!(!task.is_finished(), "valid reload stopped the runtime");

            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from_pem_file(fixture.join("test.crt.pem"))?)?;
            let client_config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut client = TlsConnector::from(Arc::new(client_config))
                .connect(
                    ServerName::try_from("reload.example")?,
                    TcpStream::connect(listen).await?,
                )
                .await
                .context("valid watched-file reload did not apply its route")?;
            client.write_all(b"x").await?;
            let mut response = [0; 8];
            client.read_exact(&mut response).await?;
            assert_eq!(&response, b"reloaded");
            client.shutdown().await?;
            upstream_task.await??;

            task.abort();
            let _ = task.await;
            Ok::<_, anyhow::Error>(())
        })
    }
}
