use crate::capture::{CaptureFlow, CaptureHub};
use crate::cert::CertificateAuthority;
use crate::dns::resolve_host;
use crate::domain::{normalize_dns_name, DomainPattern};
use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::timeout;
use tokio_rustls::{server::StartHandshake, LazyConfigAcceptor, TlsConnector};
use tracing::{debug, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 512;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Route {
    pub pattern: DomainPattern,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub verify: bool,
    pub verify_name: Option<String>,
}

impl Route {
    pub fn parse(spec: &str) -> Result<Self> {
        let (pattern, target) = spec.split_once('=').ok_or_else(|| {
            anyhow!("route must be DOMAIN=tls://HOST:PORT or DOMAIN=tcp://HOST:PORT")
        })?;
        let pattern = DomainPattern::parse(pattern)?;
        let (tls, target) = if let Some(rest) = target.strip_prefix("tcp://") {
            (false, rest)
        } else if let Some(rest) = target.strip_prefix("tls://") {
            (true, rest)
        } else {
            bail!("route upstream must start with tls:// or tcp://");
        };
        let (host, port) = split_host_port(target)?;
        Ok(Self {
            pattern,
            host,
            port,
            tls,
            verify: true,
            verify_name: None,
        })
    }

    fn matches(&self, name: &str) -> bool {
        self.pattern.matches_normalized_name(name)
    }
}

fn split_host_port(target: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed upstream address"))?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| anyhow!("invalid upstream address suffix"))?,
            )
        };
        (host, port)
    } else if target.parse::<IpAddr>().is_ok() {
        (target, None)
    } else if let Some((host, port)) = target.rsplit_once(':') {
        (host, Some(port))
    } else {
        (target, None)
    };
    if host.is_empty() || host.contains(['/', '@', '[', ']']) {
        bail!("invalid upstream host");
    }
    if host.parse::<IpAddr>().is_err() {
        normalize_dns_name(host)?;
    }
    let port = port
        .context("upstream port is required")?
        .parse::<u16>()
        .context("invalid upstream port")?;
    if port == 0 {
        bail!("upstream port must be nonzero");
    }
    Ok((host.to_owned(), port))
}

/// A route with verify=false skips trust and hostname checks but still checks
/// the server's handshake signature against its presented certificate.
#[derive(Debug)]
struct NoCertificateValidation;

impl ServerCertVerifier for NoCertificateValidation {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn select_route<'a>(routes: &'a [Route], name: &str) -> Option<&'a Route> {
    routes
        .iter()
        .filter(|route| route.matches(name))
        .max_by_key(|route| route.pattern.specificity())
}

#[derive(Clone, Copy)]
enum MatchedPolicy<'a> {
    Hold(&'a DomainPattern),
    Passthrough(&'a DomainPattern),
    Route(&'a Route),
}

impl MatchedPolicy<'_> {
    fn pattern(&self) -> &DomainPattern {
        match self {
            Self::Hold(pattern) | Self::Passthrough(pattern) => pattern,
            Self::Route(route) => &route.pattern,
        }
    }
}

fn select_policy<'a>(
    config: &'a ProxyConfig,
    name: &str,
    has_client_sni: bool,
) -> Option<MatchedPolicy<'a>> {
    let mut selected = select_route(&config.routes, name).map(MatchedPolicy::Route);
    if !has_client_sni {
        return selected;
    }

    for candidate in config
        .hold_domains
        .iter()
        .filter(|pattern| pattern.matches_normalized_name(name))
        .map(MatchedPolicy::Hold)
        .chain(
            config
                .exclude_domains
                .iter()
                .filter(|pattern| pattern.matches_normalized_name(name))
                .map(MatchedPolicy::Passthrough),
        )
    {
        if selected.as_ref().is_none_or(|current| {
            candidate.pattern().specificity() > current.pattern().specificity()
        }) {
            selected = Some(candidate);
        }
    }
    selected
}

fn format_upstream_uri(tls: bool, host: &str, port: u16) -> String {
    let scheme = if tls { "tls" } else { "tcp" };
    if matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        format!("{scheme}://[{host}]:{port}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub default_upstream_port: u16,
    pub resolver: SocketAddr,
    pub ca: CertificateAuthority,
    pub routes: Vec<Route>,
    pub hold_domains: Vec<DomainPattern>,
    pub exclude_domains: Vec<DomainPattern>,
    pub default_host: Option<String>,
    pub upstream_client: Arc<ClientConfig>,
    pub capture: Option<Arc<CaptureHub>>,
    /// Changes when the downstream signing CA material changes.
    pub ca_revision: u64,
    /// Changes when the verified upstream trust material changes.
    pub upstream_trust_revision: u64,
}

pub fn build_upstream_client(extra_ca: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = extra_ca {
        let mut added = 0;
        for cert in CertificateDer::pem_file_iter(path).context("open upstream CA file")? {
            roots
                .add(cert.context("parse upstream CA certificate")?)
                .context("invalid upstream CA certificate")?;
            added += 1;
        }
        if added == 0 {
            bail!("upstream CA file contains no certificates");
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub struct Proxy {
    listener: TcpListener,
    config: watch::Sender<Arc<ProxyConfig>>,
}

#[derive(Clone)]
pub struct ProxyConfigHandle {
    config: watch::Sender<Arc<ProxyConfig>>,
}

pub struct ProxyConfigUpdate {
    config: watch::Sender<Arc<ProxyConfig>>,
    next: Arc<ProxyConfig>,
}

impl ProxyConfigUpdate {
    pub fn publish(self) {
        self.config.send_replace(self.next);
    }
}

impl ProxyConfigHandle {
    pub fn prepare_replace(&self, config: ProxyConfig) -> Result<ProxyConfigUpdate> {
        let current = self.config.borrow();
        if config.listen != current.listen {
            bail!(
                "TLS listener address cannot change from {} to {} during reload",
                current.listen,
                config.listen
            );
        }
        drop(current);
        Ok(ProxyConfigUpdate {
            config: self.config.clone(),
            next: Arc::new(config),
        })
    }

    pub fn replace(&self, config: ProxyConfig) -> Result<()> {
        self.prepare_replace(config)?.publish();
        Ok(())
    }
}

impl Proxy {
    pub async fn bind(config: ProxyConfig) -> Result<Self> {
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("bind TLS listener {}", config.listen))?;
        let (config, _) = watch::channel(Arc::new(config));
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn config_handle(&self) -> ProxyConfigHandle {
        ProxyConfigHandle {
            config: self.config.clone(),
        }
    }

    pub async fn serve(self) -> Result<()> {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let (socket, peer) = self.listener.accept().await?;
            let local = socket
                .local_addr()
                .context("get local TLS listener address")?;
            let mut log = ConnectionLog::new(peer, local);
            log.debug("accepted");
            let permit = permits.clone().acquire_owned().await?;
            let config = self.config.subscribe();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = handle(socket, config, &mut log).await {
                    log.warn(&error);
                }
            });
        }
    }
}

struct ConnectionLog {
    peer: SocketAddr,
    local: SocketAddr,
    sni: Option<String>,
    host: Option<String>,
    started: Instant,
}

impl ConnectionLog {
    fn new(peer: SocketAddr, local: SocketAddr) -> Self {
        Self {
            peer,
            local,
            sni: None,
            host: None,
            started: Instant::now(),
        }
    }

    fn debug(&self, event: &str) {
        debug!(
            client = %self.peer,
            local = %self.local,
            sni = self.sni.as_deref().unwrap_or("-"),
            host = self.host.as_deref().unwrap_or("-"),
            event,
            "proxy connection"
        );
    }

    fn configured_route(&self, route: &str, upstream: &str, verify: &str) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            route,
            upstream,
            verify,
            "matched configured route"
        );
    }

    fn host_upstream(&self, upstream: &str, verify: &str) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            upstream,
            verify,
            "using host as upstream"
        );
    }

    fn tls_passthrough(&self, upstream: &str) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            upstream,
            "passing through TLS without interception"
        );
    }

    fn held(&self) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            "holding TLS connection without replying"
        );
    }

    fn hold_closed(&self, discarded: u64) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            client_bytes_discarded = discarded,
            duration_ms = self.started.elapsed().as_millis(),
            "held TLS connection closed by client"
        );
    }

    fn upstream_connected(&self, address: SocketAddr) {
        debug!(
            client = %self.peer,
            local = %self.local,
            sni = self.sni.as_deref().unwrap_or("-"),
            host = self.host.as_deref().unwrap_or("-"),
            upstream = %address,
            "connected to upstream"
        );
    }

    fn closed(&self, sent: u64, received: u64) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            client_to_upstream_bytes = sent,
            upstream_to_client_bytes = received,
            duration_ms = self.started.elapsed().as_millis(),
            "proxy connection closed"
        );
    }

    fn reconfigured(&self) {
        info!(
            client = %self.peer,
            host = self.host.as_deref().unwrap_or("-"),
            duration_ms = self.started.elapsed().as_millis(),
            "closed proxy connection after configuration changed its policy"
        );
    }

    fn warn(&self, error: &anyhow::Error) {
        warn!(
            client = %self.peer,
            local = %self.local,
            sni = self.sni.as_deref().unwrap_or("-"),
            host = self.host.as_deref().unwrap_or("-"),
            error = %format_args!("{error:#}"),
            "proxy connection failed"
        );
    }
}

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

struct RecordingStream {
    inner: TcpStream,
    recorded: Vec<u8>,
    recording: bool,
}

impl RecordingStream {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            recorded: Vec::new(),
            recording: true,
        }
    }

    fn stop_recording(&mut self) {
        self.recording = false;
        self.recorded.clear();
    }

    fn into_parts(self) -> (TcpStream, Vec<u8>) {
        (self.inner, self.recorded)
    }
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let previous_len = buffer.filled().len();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, std::task::Poll::Ready(Ok(()))) && this.recording {
            this.recorded
                .extend_from_slice(&buffer.filled()[previous_len..]);
        }
        result
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConnectionPlan {
    Hold {
        name: String,
    },
    Passthrough {
        name: String,
        port: u16,
        resolver: Option<SocketAddr>,
    },
    Intercept {
        name: String,
        target_host: String,
        target_port: u16,
        target_tls: bool,
        verify: bool,
        verify_name: String,
        resolver: Option<SocketAddr>,
        ca_revision: u64,
        upstream_trust_revision: Option<u64>,
    },
}

impl ConnectionPlan {
    fn name(&self) -> &str {
        match self {
            Self::Hold { name } | Self::Passthrough { name, .. } | Self::Intercept { name, .. } => {
                name
            }
        }
    }
}

fn connection_plan(config: &ProxyConfig, client_sni: Option<&str>) -> Result<ConnectionPlan> {
    let name = client_sni
        .map(str::to_owned)
        .or_else(|| config.default_host.clone())
        .ok_or_else(|| {
            anyhow!("TLS ClientHello has no SNI; set proxy.default_host for this client")
        })?;

    let (target_host, target_port, target_tls, verify, verify_name) =
        match select_policy(config, &name, client_sni.is_some()) {
            Some(MatchedPolicy::Hold(_)) => return Ok(ConnectionPlan::Hold { name }),
            Some(MatchedPolicy::Passthrough(_)) => {
                return Ok(ConnectionPlan::Passthrough {
                    name,
                    port: config.default_upstream_port,
                    resolver: Some(config.resolver),
                });
            }
            Some(MatchedPolicy::Route(route)) => (
                route.host.clone(),
                route.port,
                route.tls,
                route.verify,
                route.verify_name.clone().unwrap_or_else(|| name.clone()),
            ),
            None => (
                name.clone(),
                config.default_upstream_port,
                true,
                true,
                name.clone(),
            ),
        };
    let resolver = target_host
        .parse::<IpAddr>()
        .is_err()
        .then_some(config.resolver);
    Ok(ConnectionPlan::Intercept {
        name,
        target_host,
        target_port,
        target_tls,
        verify,
        verify_name,
        resolver,
        ca_revision: config.ca_revision,
        upstream_trust_revision: (target_tls && verify).then_some(config.upstream_trust_revision),
    })
}

async fn handle(
    socket: TcpStream,
    mut configs: watch::Receiver<Arc<ProxyConfig>>,
    log: &mut ConnectionLog,
) -> Result<()> {
    let incoming = LazyConfigAcceptor::new(
        rustls::server::Acceptor::default(),
        RecordingStream::new(socket),
    );
    let start = timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .context("timed out waiting for ClientHello")??;
    let client_sni = start
        .client_hello()
        .server_name()
        .map(normalize_dns_name)
        .transpose()?;
    if let Some(name) = &client_sni {
        log.sni = Some(name.clone());
    }
    let config = configs.borrow().clone();
    let plan = connection_plan(&config, client_sni.as_deref())?;
    log.host = Some(plan.name().to_owned());
    log.debug("client_hello");

    if matches!(plan, ConnectionPlan::Hold { .. }) {
        log.held();
        let accepted = start.accepted;
        let (client, recorded) = start.io.into_parts();
        let initial_discarded = recorded.len() as u64;
        drop(recorded);
        drop(accepted);
        drop(config);
        let discarded = hold_until_client_closes(client).await?;
        log.hold_closed(initial_discarded.saturating_add(discarded));
        return Ok(());
    }

    let establish = establish_connection(start, config, &plan, log);
    tokio::pin!(establish);
    let established = loop {
        let changed_result = {
            let changed = configs.changed();
            tokio::pin!(changed);
            // Poll policy changes first so a simultaneously ready reload wins
            // over completion of setup performed with the previous policy.
            match futures::future::select(changed, establish.as_mut()).await {
                futures::future::Either::Left((changed, _)) => changed,
                futures::future::Either::Right((result, _)) => break result?,
            }
        };
        if changed_result.is_err() {
            break establish.await?;
        }
        let next = configs.borrow_and_update().clone();
        let still_valid =
            connection_plan(&next, client_sni.as_deref()).is_ok_and(|next_plan| next_plan == plan);
        if !still_valid {
            log.reconfigured();
            return Ok(());
        }
    };

    relay_with_reload(
        established.client,
        established.upstream,
        established.capture,
        established.initial_sent,
        &mut configs,
        &client_sni,
        &plan,
        log,
    )
    .await
}

struct EstablishedConnection {
    client: Box<dyn Duplex>,
    upstream: Box<dyn Duplex>,
    capture: Option<Arc<CaptureHub>>,
    initial_sent: u64,
}

async fn establish_connection(
    mut start: StartHandshake<RecordingStream>,
    config: Arc<ProxyConfig>,
    plan: &ConnectionPlan,
    log: &ConnectionLog,
) -> Result<EstablishedConnection> {
    match &plan {
        ConnectionPlan::Hold { .. } => {
            unreachable!("hold plans are handled before upstream setup")
        }
        ConnectionPlan::Passthrough {
            name,
            port,
            resolver,
        } => {
            let upstream_uri = format_upstream_uri(true, name, *port);
            log.tls_passthrough(&upstream_uri);
            let addresses = resolve_host(name, *port, resolver.unwrap_or(config.resolver))
                .await
                .with_context(|| format!("resolve passthrough upstream {name}"))?;
            let mut upstream = connect_first(&addresses).await?;
            log.upstream_connected(upstream.peer_addr()?);
            let (client, recorded) = start.io.into_parts();
            upstream
                .write_all(&recorded)
                .await
                .context("client_to_upstream write recorded ClientHello failed")?;
            Ok(EstablishedConnection {
                client: Box::new(client),
                upstream: Box::new(upstream),
                capture: None,
                initial_sent: recorded.len() as u64,
            })
        }
        ConnectionPlan::Intercept {
            name,
            target_host,
            target_port,
            target_tls,
            verify,
            verify_name,
            resolver,
            ..
        } => {
            let offered_alpn: Vec<Vec<u8>> = start
                .client_hello()
                .alpn()
                .map(|values| values.map(|value| value.to_vec()).collect())
                .unwrap_or_default();
            start.io.stop_recording();
            let upstream_uri = format_upstream_uri(*target_tls, target_host, *target_port);
            let verification_name = if *target_tls && *verify {
                verify_name.as_str()
            } else {
                ""
            };
            if let Some(route) = select_route(&config.routes, name) {
                log.configured_route(route.pattern.as_str(), &upstream_uri, verification_name);
            } else {
                log.host_upstream(&upstream_uri, verification_name);
            }
            let addresses = resolve_host(
                target_host,
                *target_port,
                resolver.unwrap_or(config.resolver),
            )
            .await
            .with_context(|| format!("resolve upstream {target_host}"))?;
            let tcp = connect_first(&addresses).await?;
            log.upstream_connected(tcp.peer_addr()?);

            let (upstream, selected_alpn): (Box<dyn Duplex>, Option<Vec<u8>>) = if *target_tls {
                let mut client_config = (*config.upstream_client).clone();
                client_config.alpn_protocols = offered_alpn;
                if !*verify {
                    // Do not share TLS session tickets with routes that validate certificates.
                    client_config.resumption = rustls::client::Resumption::disabled();
                    client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(NoCertificateValidation));
                }
                let server_name = ServerName::try_from(verify_name.clone())
                    .context("invalid upstream TLS verification name")?;
                let stream = timeout(
                    HANDSHAKE_TIMEOUT,
                    TlsConnector::from(Arc::new(client_config)).connect(server_name, tcp),
                )
                .await
                .context("upstream TLS handshake timeout")?
                .with_context(|| format!("upstream TLS handshake failed for {verify_name}"))?;
                let alpn = stream.get_ref().1.alpn_protocol().map(|v| v.to_vec());
                (Box::new(stream), alpn)
            } else {
                (Box::new(tcp), None)
            };

            let leaf = config.ca.for_host(name).await?;
            let mut server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(leaf.certs.clone(), leaf.key.clone_key())
                .context("configure generated leaf certificate")?;
            if let Some(protocol) = selected_alpn {
                server_config.alpn_protocols = vec![protocol];
            }
            let client = timeout(
                HANDSHAKE_TIMEOUT,
                start.into_stream(Arc::new(server_config)),
            )
            .await
            .context("downstream TLS handshake timeout")??;
            log.debug("tls_handshake_complete");
            Ok(EstablishedConnection {
                client: Box::new(client),
                upstream,
                capture: config.capture.clone(),
                initial_sent: 0,
            })
        }
    }
}

async fn hold_until_client_closes<R>(mut client: R) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    tokio::io::copy(&mut client, &mut tokio::io::sink())
        .await
        .context("read held TLS connection")
}

#[allow(clippy::too_many_arguments)]
async fn relay_with_reload<C, U>(
    client: C,
    upstream: U,
    capture: Option<Arc<CaptureHub>>,
    initial_sent: u64,
    configs: &mut watch::Receiver<Arc<ProxyConfig>>,
    client_sni: &Option<String>,
    plan: &ConnectionPlan,
    log: &ConnectionLog,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let latest = configs.borrow_and_update().clone();
    if !connection_plan(&latest, client_sni.as_deref()).is_ok_and(|next| next == *plan) {
        log.reconfigured();
        return Ok(());
    }
    let flow = capture.map(|hub| hub.flow(log.peer, log.local));
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let transfer = async {
        futures::try_join!(
            copy_with_capture(&mut client_read, &mut upstream_write, flow.as_ref(), true),
            copy_with_capture(&mut upstream_read, &mut client_write, flow.as_ref(), false)
        )
    };
    tokio::pin!(transfer);
    loop {
        let changed_result = {
            let changed = configs.changed();
            tokio::pin!(changed);
            match futures::future::select(transfer.as_mut(), changed).await {
                futures::future::Either::Left((result, _)) => {
                    let (sent, received) = result?;
                    if let Some(flow) = &flow {
                        flow.close();
                    }
                    log.closed(initial_sent.saturating_add(sent), received);
                    return Ok(());
                }
                futures::future::Either::Right((changed, _)) => changed,
            }
        };
        if changed_result.is_err() {
            let (sent, received) = transfer.await?;
            if let Some(flow) = &flow {
                flow.close();
            }
            log.closed(initial_sent.saturating_add(sent), received);
            return Ok(());
        }
        let next = configs.borrow_and_update().clone();
        let still_valid =
            connection_plan(&next, client_sni.as_deref()).is_ok_and(|next_plan| next_plan == *plan);
        if !still_valid {
            if let Some(flow) = &flow {
                flow.close();
            }
            log.reconfigured();
            return Ok(());
        }
    }
}

async fn connect_first(addresses: &[SocketAddr]) -> Result<TcpStream> {
    let mut last_error = None;
    for &address in addresses {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(socket)) => return Ok(socket),
            Ok(Err(error)) => last_error = Some(format!("{address}: {error}")),
            Err(_) => last_error = Some(format!("{address}: timed out")),
        }
    }
    bail!(
        "could not connect to any upstream address: {}",
        last_error.unwrap_or_else(|| "no addresses".into())
    )
}

async fn copy_with_capture<R, W>(
    reader: &mut R,
    writer: &mut W,
    flow: Option<&CaptureFlow>,
    client_to_server: bool,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    let direction = if client_to_server {
        "client_to_upstream"
    } else {
        "upstream_to_client"
    };
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) => n,
            Err(error) if is_missing_close_notify(&error) => 0,
            Err(error) => return Err(error).with_context(|| format!("{direction} read failed")),
        };
        if n == 0 {
            // The reader has reached EOF. A peer that already closed may
            // reject the half-close even though no more payload remains.
            match writer.shutdown().await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("{direction} shutdown failed"))
                }
            }
            return Ok(total);
        }
        writer
            .write_all(&buf[..n])
            .await
            .with_context(|| format!("{direction} write failed"))?;
        total += n as u64;
        if let Some(flow) = flow {
            if client_to_server {
                flow.client_to_server(&buf[..n]);
            } else {
                flow.server_to_client(&buf[..n]);
            }
        }
    }
}

fn is_missing_close_notify(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::UnexpectedEof
        && error
            .to_string()
            .starts_with("peer closed connection without sending TLS close_notify")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::ReadBuf;

    struct ErrorReader(&'static str);

    struct ErrorWriter {
        written: Vec<u8>,
        fail_write: bool,
        shutdown_error: io::ErrorKind,
    }

    fn test_config() -> ProxyConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
        let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
        ProxyConfig {
            listen: "127.0.0.1:443".parse().unwrap(),
            default_upstream_port: 443,
            resolver: "127.0.0.1:5353".parse().unwrap(),
            ca: CertificateAuthority::new(&cert, &key).unwrap(),
            routes: Vec::new(),
            hold_domains: Vec::new(),
            exclude_domains: Vec::new(),
            default_host: None,
            upstream_client: build_upstream_client(None).unwrap(),
            capture: None,
            ca_revision: 0,
            upstream_trust_revision: 0,
        }
    }

    impl AsyncWrite for ErrorWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.fail_write {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            } else {
                this.written.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(self.shutdown_error.into()))
        }
    }

    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, self.0)))
        }
    }

    #[test]
    fn route_matching_uses_dns_domain_rules() {
        let routes = vec![
            Route::parse("*.example.com=tls://127.0.0.1:8443").unwrap(),
            Route::parse("api.example.com=tcp://127.0.0.1:8080").unwrap(),
        ];
        assert_eq!(select_route(&routes, "api.example.com").unwrap().port, 8080);
        assert_eq!(
            select_route(&routes, "deep.api.example.com").unwrap().port,
            8080
        );
        assert_eq!(select_route(&routes, "www.example.com").unwrap().port, 8443);
        assert!(select_route(&routes, "example.com").is_none());
        assert!(select_route(&routes, "badexample.com").is_none());
    }

    #[test]
    fn plain_route_matches_apex_and_subdomains_but_not_partial_labels() {
        let routes = vec![Route::parse("example.com=tcp://127.0.0.1:8000").unwrap()];
        for name in ["example.com", "a.example.com", "b.a.example.com"] {
            assert!(select_route(&routes, name).is_some(), "{name}");
        }
        for name in ["badexample.com", "example.com.evil"] {
            assert!(select_route(&routes, name).is_none(), "{name}");
        }
    }

    #[test]
    fn route_selection_prefers_longest_suffix_then_plain_pattern_then_catch_all() {
        let routes = vec![
            Route::parse("a.example.com=tcp://127.0.0.1:8001").unwrap(),
            Route::parse("*.example.com=tcp://127.0.0.1:8002").unwrap(),
            Route::parse("*=tcp://127.0.0.1:8003").unwrap(),
            Route::parse("example.com=tcp://127.0.0.1:8004").unwrap(),
        ];
        assert_eq!(select_route(&routes, "a.example.com").unwrap().port, 8001);
        assert_eq!(select_route(&routes, "b.example.com").unwrap().port, 8004);
        assert_eq!(select_route(&routes, "example.com").unwrap().port, 8004);
        assert_eq!(
            select_route(&routes, "deep.a.example.com").unwrap().port,
            8001
        );
        assert_eq!(select_route(&routes, "other.test").unwrap().port, 8003);

        let short_routes = vec![
            Route::parse("a=tcp://127.0.0.1:8004").unwrap(),
            Route::parse("*=tcp://127.0.0.1:8003").unwrap(),
        ];
        assert_eq!(select_route(&short_routes, "x.a").unwrap().port, 8004);
        for invalid in [
            "*.",
            "api*.example.com",
            "api.*.example.com",
            "**.example.com",
        ] {
            assert!(Route::parse(&format!("{invalid}=tls://127.0.0.1:8000")).is_err());
        }
    }

    #[test]
    fn route_upstream_requires_scheme_host_and_nonzero_port() {
        for invalid in [
            "example.com=127.0.0.1:443",
            "example.com=tls://127.0.0.1",
            "example.com=tcp://upstream.example",
            "example.com=tls://127.0.0.1:0",
            "example.com=tls://[2001:db8::1]",
        ] {
            assert!(Route::parse(invalid).is_err(), "{invalid}");
        }

        let route = Route::parse("example.com=tls://[2001:db8::1]:8443").unwrap();
        assert_eq!(route.host, "2001:db8::1");
        assert_eq!(route.port, 8443);
    }

    #[test]
    fn upstream_uri_includes_scheme_port_and_ipv6_brackets() {
        assert_eq!(
            format_upstream_uri(true, "upstream.example", 443),
            "tls://upstream.example:443"
        );
        assert_eq!(
            format_upstream_uri(false, "192.0.2.1", 8080),
            "tcp://192.0.2.1:8080"
        );
        assert_eq!(
            format_upstream_uri(true, "2001:db8::1", 8443),
            "tls://[2001:db8::1]:8443"
        );
    }

    #[test]
    fn proxy_exclusion_uses_actual_sni_and_beats_a_less_specific_route() {
        let mut config = test_config();
        config.default_host = Some("excluded.example".to_owned());
        config.exclude_domains = vec![DomainPattern::parse("excluded.example").unwrap()];
        config.routes = vec![Route::parse("*=tcp://127.0.0.1:8080").unwrap()];

        assert!(matches!(
            connection_plan(&config, Some("excluded.example")).unwrap(),
            ConnectionPlan::Passthrough {
                name,
                port: 443,
                ..
            } if name == "excluded.example"
        ));
        assert!(matches!(
            connection_plan(&config, None).unwrap(),
            ConnectionPlan::Intercept {
                target_port: 8080,
                target_tls: false,
                ..
            }
        ));
    }

    #[test]
    fn proxy_hold_uses_actual_sni_and_beats_less_specific_policies() {
        let mut config = test_config();
        config.default_host = Some("held.example".to_owned());
        config.hold_domains = vec![DomainPattern::parse("held.example").unwrap()];
        config.exclude_domains = vec![DomainPattern::parse("*.held.example").unwrap()];
        config.routes = vec![Route::parse("*=tcp://127.0.0.1:8080").unwrap()];

        assert!(matches!(
            connection_plan(&config, Some("held.example")).unwrap(),
            ConnectionPlan::Hold { name } if name == "held.example"
        ));
        assert!(matches!(
            connection_plan(&config, Some("deep.held.example")).unwrap(),
            ConnectionPlan::Hold { name } if name == "deep.held.example"
        ));
        assert!(matches!(
            connection_plan(&config, None).unwrap(),
            ConnectionPlan::Intercept {
                target_port: 8080,
                target_tls: false,
                ..
            }
        ));
    }

    #[test]
    fn proxy_route_beats_less_specific_hold_and_exclusion_patterns() {
        let mut config = test_config();
        config.hold_domains = vec![DomainPattern::parse("*").unwrap()];
        config.exclude_domains = vec![DomainPattern::parse("*.example").unwrap()];
        config.routes = vec![Route::parse("routed.example=tcp://127.0.0.1:8080").unwrap()];

        assert!(matches!(
            connection_plan(&config, Some("routed.example")).unwrap(),
            ConnectionPlan::Intercept {
                target_port: 8080,
                target_tls: false,
                ..
            }
        ));
    }

    #[test]
    fn proxy_exclusion_beats_less_specific_hold_and_route_patterns() {
        let mut config = test_config();
        config.hold_domains = vec![DomainPattern::parse("*").unwrap()];
        config.exclude_domains = vec![DomainPattern::parse("passthrough.example").unwrap()];
        config.routes = vec![Route::parse("*.example=tcp://127.0.0.1:8080").unwrap()];

        assert!(matches!(
            connection_plan(&config, Some("passthrough.example")).unwrap(),
            ConnectionPlan::Passthrough { name, .. } if name == "passthrough.example"
        ));
    }

    #[test]
    fn proxy_longer_wildcard_beats_a_shorter_plain_pattern() {
        let mut config = test_config();
        config.hold_domains = vec![DomainPattern::parse("example.com").unwrap()];
        config.routes = vec![Route::parse("*.api.example.com=tcp://127.0.0.1:8080").unwrap()];

        assert!(matches!(
            connection_plan(&config, Some("host.api.example.com")).unwrap(),
            ConnectionPlan::Intercept {
                target_port: 8080,
                target_tls: false,
                ..
            }
        ));
    }

    #[test]
    fn held_connection_waits_for_client_eof() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut client, server) = tokio::io::duplex(64);
            let held = tokio::spawn(hold_until_client_closes(server));

            client.write_all(b"more client bytes").await.unwrap();
            tokio::task::yield_now().await;
            assert!(!held.is_finished());

            drop(client);
            assert_eq!(held.await.unwrap().unwrap(), 17);
        });
    }

    #[test]
    fn effective_policy_changes_only_for_relevant_reload_fields() {
        let mut config = test_config();
        config.routes = vec![
            Route::parse("active.example=tcp://127.0.0.1:8080").unwrap(),
            Route::parse("other.example=tcp://127.0.0.1:8081").unwrap(),
        ];
        let original = connection_plan(&config, Some("active.example")).unwrap();

        config.routes[1] = Route::parse("other.example=tcp://127.0.0.1:9091").unwrap();
        config.resolver = "127.0.0.1:5454".parse().unwrap();
        assert_eq!(
            connection_plan(&config, Some("active.example")).unwrap(),
            original,
            "an unrelated route and resolver changes must not close a numeric-route connection"
        );

        config.routes[0] = Route::parse("active.example=tcp://127.0.0.1:9090").unwrap();
        assert_ne!(
            connection_plan(&config, Some("active.example")).unwrap(),
            original
        );
    }

    #[test]
    fn only_rustls_missing_close_notify_is_a_normal_eof() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut rustls_eof = ErrorReader(
                "peer closed connection without sending TLS close_notify: https://docs.rs/rustls/",
            );
            let mut writer = tokio::io::sink();
            assert_eq!(
                copy_with_capture(&mut rustls_eof, &mut writer, None, true)
                    .await
                    .unwrap(),
                0
            );

            let mut other_eof = ErrorReader("truncated application data");
            let mut writer = tokio::io::sink();
            assert!(copy_with_capture(&mut other_eof, &mut writer, None, true)
                .await
                .is_err());
        });
    }

    #[test]
    fn broken_pipe_on_shutdown_after_eof_is_normal_but_write_failure_is_not() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut reader = b"complete response".as_slice();
            let mut writer = ErrorWriter {
                written: Vec::new(),
                fail_write: false,
                shutdown_error: io::ErrorKind::BrokenPipe,
            };
            assert_eq!(
                copy_with_capture(&mut reader, &mut writer, None, false)
                    .await
                    .unwrap(),
                b"complete response".len() as u64
            );
            assert_eq!(writer.written, b"complete response");

            let mut reader = b"undelivered response".as_slice();
            let mut writer = ErrorWriter {
                written: Vec::new(),
                fail_write: true,
                shutdown_error: io::ErrorKind::BrokenPipe,
            };
            let error = copy_with_capture(&mut reader, &mut writer, None, false)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("upstream_to_client write failed"));
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert!(writer.written.is_empty());

            let mut reader = b"complete response".as_slice();
            let mut writer = ErrorWriter {
                written: Vec::new(),
                fail_write: false,
                shutdown_error: io::ErrorKind::ConnectionReset,
            };
            let error = copy_with_capture(&mut reader, &mut writer, None, false)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("upstream_to_client shutdown failed"));
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::ConnectionReset
            );
        });
    }
}
