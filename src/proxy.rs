use crate::capture::{CaptureFlow, CaptureHub};
use crate::cert::{normalize_dns_name, CertificateAuthority};
use crate::dns::resolve_host;
use anyhow::{anyhow, bail, Context, Result};
use chrono::{SecondsFormat, Utc};
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
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 512;

#[derive(Debug, Clone)]
pub struct Route {
    pub pattern: String,
    pub host: String,
    pub port: Option<u16>,
    pub tls: bool,
    pub verify: bool,
    pub verify_name: Option<String>,
}

impl Route {
    pub fn parse(spec: &str) -> Result<Self> {
        let (pattern, target) = spec.split_once('=').ok_or_else(|| {
            anyhow!("route must be DOMAIN=tls://HOST[:PORT] or DOMAIN=tcp://HOST[:PORT]")
        })?;
        let pattern = if let Some(rest) = pattern.strip_prefix("*.") {
            format!("*.{}", normalize_dns_name(rest)?)
        } else {
            normalize_dns_name(pattern)?
        };
        let (tls, target) = if let Some(rest) = target.strip_prefix("tcp://") {
            (false, rest)
        } else if let Some(rest) = target.strip_prefix("tls://") {
            (true, rest)
        } else {
            (true, target)
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
        if let Some(suffix) = self.pattern.strip_prefix("*.") {
            name.len() > suffix.len() + 1
                && name.ends_with(suffix)
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
        } else {
            self.pattern == name
        }
    }
}

fn split_host_port(target: &str) -> Result<(String, Option<u16>)> {
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
        .map(|value| value.parse::<u16>().context("invalid upstream port"))
        .transpose()?;
    if port == Some(0) {
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
        .max_by_key(|route| route.pattern.len())
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub default_upstream_port: u16,
    pub resolver: SocketAddr,
    pub ca: CertificateAuthority,
    pub routes: Vec<Route>,
    pub default_host: Option<String>,
    pub upstream_client: Arc<ClientConfig>,
    pub capture: Option<Arc<CaptureHub>>,
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
    config: Arc<ProxyConfig>,
}

impl Proxy {
    pub async fn bind(config: ProxyConfig) -> Result<Self> {
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("bind TLS listener {}", config.listen))?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn serve(self) -> Result<()> {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let (socket, peer) = self.listener.accept().await?;
            let local = socket
                .local_addr()
                .context("get local TLS listener address")?;
            let mut log = ConnectionLog::new(peer, local);
            log.info("accepted");
            let permit = permits.clone().acquire_owned().await?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = handle(socket, config, &mut log).await {
                    log.error(&format!("{error:#}"));
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

    fn info(&self, message: &str) {
        self.write("INFO", message);
    }

    fn error(&self, message: &str) {
        self.write("ERROR", message);
    }

    fn write(&self, level: &str, message: &str) {
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let sni = self.sni.as_deref().unwrap_or("-");
        let host = self.host.as_deref().unwrap_or("-");
        eprintln!(
            "{timestamp} {level} client={} local={} sni={sni} host={host} {message}",
            self.peer, self.local
        );
    }
}

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

async fn handle(
    socket: TcpStream,
    config: Arc<ProxyConfig>,
    log: &mut ConnectionLog,
) -> Result<()> {
    let incoming = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), socket);
    let start = timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .context("timed out waiting for ClientHello")??;
    let client_sni = start.client_hello().server_name().map(str::to_owned);
    let had_sni = client_sni.is_some();
    let name = client_sni
        .or_else(|| config.default_host.clone())
        .ok_or_else(|| {
            anyhow!("TLS ClientHello has no SNI; set proxy.default_host for this client")
        })?;
    let name = normalize_dns_name(&name)?;
    if had_sni {
        log.sni = Some(name.clone());
    }
    log.host = Some(name.clone());
    log.info("client_hello");
    let offered_alpn: Vec<Vec<u8>> = start
        .client_hello()
        .alpn()
        .map(|values| values.map(|value| value.to_vec()).collect())
        .unwrap_or_default();

    let route = select_route(&config.routes, &name);
    let (target_host, target_port, target_tls, verify, verify_name) = match route {
        Some(route) => (
            route.host.as_str(),
            route.port.unwrap_or(config.default_upstream_port),
            route.tls,
            route.verify,
            route.verify_name.as_deref().unwrap_or(&name),
        ),
        None => (
            name.as_str(),
            config.default_upstream_port,
            true,
            true,
            name.as_str(),
        ),
    };
    log.info(&format!(
        "route={} upstream={}://{}:{} verify={} verify_name={}",
        route
            .map(|route| route.pattern.as_str())
            .unwrap_or("default"),
        if target_tls { "tls" } else { "tcp" },
        target_host,
        target_port,
        if target_tls {
            if verify {
                "true"
            } else {
                "false"
            }
        } else {
            "-"
        },
        if target_tls { verify_name } else { "-" }
    ));
    let addresses = resolve_host(target_host, target_port, config.resolver)
        .await
        .with_context(|| format!("resolve upstream {target_host}"))?;
    let tcp = connect_first(&addresses).await?;
    log.info(&format!("upstream_connected address={}", tcp.peer_addr()?));

    let (upstream, selected_alpn): (Box<dyn Duplex>, Option<Vec<u8>>) = if target_tls {
        let mut client_config = (*config.upstream_client).clone();
        client_config.alpn_protocols = offered_alpn;
        if !verify {
            // Do not share TLS session tickets with routes that validate certificates.
            client_config.resumption = rustls::client::Resumption::disabled();
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateValidation));
        }
        let server_name = ServerName::try_from(verify_name.to_owned())
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

    let leaf = config.ca.for_host(&name).await?;
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
    log.info("tls_handshake_complete");

    let flow = config
        .capture
        .as_ref()
        .map(|hub| hub.flow(log.peer, log.local));
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let result = futures::try_join!(
        copy_with_capture(&mut client_read, &mut upstream_write, flow.as_ref(), true),
        copy_with_capture(&mut upstream_read, &mut client_write, flow.as_ref(), false)
    );
    if let Some(flow) = flow {
        flow.close();
    }
    let (sent, received) = result?;
    log.info(&format!(
        "closed client_to_upstream_bytes={sent} upstream_to_client_bytes={received} duration_ms={}",
        log.started.elapsed().as_millis()
    ));
    Ok(())
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
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::ReadBuf;

    struct ErrorReader(&'static str);

    struct ErrorWriter {
        written: Vec<u8>,
        fail_write: bool,
        shutdown_error: io::ErrorKind,
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
    fn route_matching_is_exact_or_label_bounded_suffix() {
        let routes = vec![
            Route::parse("*.example.com=127.0.0.1:8443").unwrap(),
            Route::parse("api.example.com=tcp://127.0.0.1:8080").unwrap(),
        ];
        assert_eq!(
            select_route(&routes, "api.example.com").unwrap().port,
            Some(8080)
        );
        assert_eq!(
            select_route(&routes, "www.example.com").unwrap().port,
            Some(8443)
        );
        assert!(select_route(&routes, "example.com").is_none());
        assert!(select_route(&routes, "badexample.com").is_none());
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
