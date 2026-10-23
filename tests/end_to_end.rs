use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tls_mitm::capture::start_capture;
use tls_mitm::cert::CertificateAuthority;
use tls_mitm::dns::{serve_dns, DnsConfig};
use tls_mitm::domain::DomainPattern;
use tls_mitm::proxy::{build_upstream_client, Proxy, ProxyConfig, Route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const REQUEST: &[u8] = b"client plaintext through TLS\n";
const RESPONSE: &[u8] = b"upstream plaintext through TLS\n";
const ALPN: &[u8] = b"h2";

#[test]
fn mitm_routes_tls_and_streams_decrypted_both_directions() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { timeout(Duration::from_secs(20), exercise_proxy()).await? })
}

async fn exercise_proxy() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let leaf = ca.for_host("test.example").await?;

    let mut upstream_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.certs.clone(), leaf.key.clone_key())?;
    upstream_tls.alpn_protocols = vec![ALPN.to_vec()];
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (socket, _) = upstream_listener.accept().await?;
        let mut stream = TlsAcceptor::from(Arc::new(upstream_tls))
            .accept(socket)
            .await?;
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(ALPN));
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let capture = start_capture(Some("127.0.0.1:0".parse()?), None, None).await?;
    let mut viewer = TcpStream::connect(capture.local_addr().unwrap()).await?;
    let mut global_header = [0u8; 24];
    viewer.read_exact(&mut global_header).await?;
    assert_eq!(&global_header[..8], &[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]);
    assert_eq!(u32::from_le_bytes(global_header[20..24].try_into()?), 101); // DLT_RAW

    let mut route = Route::parse(&format!(
        "test.example=tls://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    route.verify = false;
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?, // Numeric route needs no lookup.
        ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: vec![DomainPattern::parse("other.example")?],
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: Some(capture),
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![ALPN.to_vec()];
    let socket = TcpStream::connect(proxy_addr).await?;
    let client_addr = socket.local_addr()?;
    let mut client = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("test.example")?, socket)
        .await
        .context("client must validate the proxy's SNI-issued certificate")?;
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(ALPN));
    client.write_all(REQUEST).await?;
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    client.shutdown().await?;
    upstream_task.await??;

    let mut captured_request = Vec::new();
    let mut captured_response = Vec::new();
    timeout(Duration::from_secs(5), async {
        while !captured_request
            .windows(REQUEST.len())
            .any(|part| part == REQUEST)
            || !captured_response
                .windows(RESPONSE.len())
                .any(|part| part == RESPONSE)
        {
            let (src, dst, payload) = read_pcap_tcp_payload(&mut viewer).await?;
            if src == client_addr && dst == proxy_addr {
                captured_request.extend_from_slice(&payload);
            } else if src == proxy_addr && dst == client_addr {
                captured_response.extend_from_slice(&payload);
            } else {
                anyhow::bail!("unexpected capture endpoints {src} -> {dst}");
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("timed out waiting for decrypted PCAP packets")??;

    proxy_task.abort();
    Ok(())
}

async fn read_pcap_tcp_payload(
    viewer: &mut TcpStream,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>)> {
    let mut record_header = [0u8; 16];
    viewer.read_exact(&mut record_header).await?;
    let captured_len = u32::from_le_bytes(record_header[8..12].try_into()?) as usize;
    let original_len = u32::from_le_bytes(record_header[12..16].try_into()?) as usize;
    assert_eq!(captured_len, original_len);
    assert!((40..=65535).contains(&captured_len));
    let mut packet = vec![0; captured_len];
    viewer.read_exact(&mut packet).await?;

    assert_eq!(packet[0] >> 4, 4); // Both test endpoints use loopback IPv4.
    assert_eq!(packet[9], 6); // TCP
    let ip_len = usize::from(packet[0] & 0x0f) * 4;
    assert!(ip_len >= 20 && packet.len() >= ip_len + 20);
    let tcp = &packet[ip_len..];
    let tcp_len = usize::from(tcp[12] >> 4) * 4;
    assert!(tcp_len >= 20 && tcp.len() >= tcp_len);
    let src_port = u16::from_be_bytes(tcp[0..2].try_into()?);
    let dst_port = u16::from_be_bytes(tcp[2..4].try_into()?);
    let src_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16])?);
    let dst_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20])?);
    Ok((
        SocketAddr::from((src_ip, src_port)),
        SocketAddr::from((dst_ip, dst_port)),
        tcp[tcp_len..].to_vec(),
    ))
}

#[test]
fn mitm_routes_tls_client_to_plain_tcp_upstream() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { timeout(Duration::from_secs(10), exercise_tcp_route()).await? })
}

async fn exercise_tcp_route() -> Result<()> {
    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await?;
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let route = Route::parse(&format!(
        "test.example=tcp://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let socket = TcpStream::connect(proxy_addr).await?;
    let mut client = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("test.example")?, socket)
        .await?;
    client.write_all(REQUEST).await?;
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    client.shutdown().await?;
    upstream_task.await??;
    proxy_task.abort();
    Ok(())
}

#[test]
fn repeated_client_connections_reuse_the_same_sni_certificate() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        timeout(Duration::from_secs(20), exercise_cached_sni_certificate()).await?
    })
}

async fn exercise_cached_sni_certificate() -> Result<()> {
    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = upstream_listener.accept().await?;
            let mut request = vec![0; REQUEST.len()];
            stream.read_exact(&mut request).await?;
            assert_eq!(request, REQUEST);
            stream.write_all(RESPONSE).await?;
            stream.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let route = Route::parse(&format!(
        "test.example=tcp://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(proxy.serve());

    let mut issued_certificates = Vec::new();
    for _ in 0..2 {
        // A fresh client configuration forces a full handshake on both
        // connections, so TLS session resumption cannot mask a new leaf.
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from_pem_file(&cert)?)?;
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let socket = TcpStream::connect(proxy_addr).await?;
        let mut client = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("test.example")?, socket)
            .await
            .context("client must validate the proxy's SNI-issued certificate")?;
        let leaf = client
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .context("proxy did not present a leaf certificate")?;
        issued_certificates.push(leaf.as_ref().to_vec());

        client.write_all(REQUEST).await?;
        let mut response = vec![0; RESPONSE.len()];
        client.read_exact(&mut response).await?;
        assert_eq!(response, RESPONSE);
        client.shutdown().await?;
    }
    assert_eq!(issued_certificates[0], issued_certificates[1]);

    upstream_task.await??;
    proxy_task.abort();
    Ok(())
}

#[test]
fn tls_route_verifies_upstream_certificate_by_default() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(async { timeout(Duration::from_secs(10), exercise_untrusted_tls_route()).await? })
}

async fn exercise_untrusted_tls_route() -> Result<()> {
    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let leaf = ca.for_host("test.example").await?;
    let upstream_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.certs.clone(), leaf.key.clone_key())?;
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (socket, _) = upstream_listener.accept().await?;
        let _ = TlsAcceptor::from(Arc::new(upstream_tls))
            .accept(socket)
            .await;
        Ok::<_, anyhow::Error>(())
    });

    let route = Route::parse(&format!(
        "test.example=tls://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    assert!(route.verify);
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let socket = TcpStream::connect(proxy_addr).await?;
    let result = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("test.example")?, socket)
        .await;
    assert!(
        result.is_err(),
        "untrusted upstream certificate was accepted"
    );

    upstream_task.await??;
    proxy_task.abort();
    Ok(())
}

#[test]
fn mitm_uses_configured_resolver_and_default_upstream_port() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { timeout(Duration::from_secs(10), exercise_default_route()).await? })
}

async fn exercise_default_route() -> Result<()> {
    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let leaf = ca.for_host("test.example").await?;
    let upstream_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.certs.clone(), leaf.key.clone_key())?;
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (socket, _) = upstream_listener.accept().await?;
        let mut stream = TlsAcceptor::from(Arc::new(upstream_tls))
            .accept(socket)
            .await?;
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    // The proxy must send both A and AAAA lookups here. Only the A answer
    // points to our test server; no system or external resolver is involved.
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let resolver_addr = resolver.local_addr()?;
    let resolver_task = tokio::spawn(async move {
        let mut seen_a = false;
        let mut seen_aaaa = false;
        for _ in 0..2 {
            let mut query = [0u8; 512];
            let (length, peer) = resolver.recv_from(&mut query).await?;
            let query = &query[..length];
            assert_eq!(&query[12..length - 4], b"\x04test\x07example\0");
            let qtype = u16::from_be_bytes([query[length - 4], query[length - 3]]);
            let mut response = query.to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            match qtype {
                1 => {
                    assert!(!seen_a);
                    seen_a = true;
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&[
                        0xc0, 0x0c, // Compressed answer name.
                        0, 1, 0, 1, // A, IN.
                        0, 0, 0, 60, // TTL.
                        0, 4, 127, 0, 0, 1, // 127.0.0.1.
                    ]);
                }
                28 => {
                    assert!(!seen_aaaa);
                    seen_aaaa = true;
                }
                other => anyhow::bail!("unexpected DNS query type {other}"),
            }
            resolver.send_to(&response, peer).await?;
        }
        assert!(seen_a && seen_aaaa);
        Ok::<_, anyhow::Error>(())
    });

    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: upstream_addr.port(),
        resolver: resolver_addr,
        ca,
        routes: Vec::new(),
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client: build_upstream_client(Some(&cert))?,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let socket = TcpStream::connect(proxy_addr).await?;
    let mut client = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("test.example")?, socket)
        .await
        .context("client must validate the certificate issued for default-route SNI")?;
    client.write_all(REQUEST).await?;
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    client.shutdown().await?;

    resolver_task.await??;
    upstream_task.await??;
    proxy_task.abort();
    Ok(())
}

#[test]
fn excluded_proxy_domain_passes_raw_tls_to_the_real_upstream() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { timeout(Duration::from_secs(10), exercise_tls_passthrough()).await? })
}

async fn exercise_tls_passthrough() -> Result<()> {
    const NAME: &str = "host.skip.example";

    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");

    // Independent CA instances avoid sharing the generated-leaf cache. That
    // makes exact certificate equality a reliable distinction between direct
    // passthrough and a second, intercepted TLS session.
    let upstream_ca = CertificateAuthority::new(&cert, &key)?;
    let upstream_leaf = upstream_ca.for_host(NAME).await?;
    let expected_upstream_leaf = upstream_leaf.certs[0].as_ref().to_vec();
    let proxy_ca = CertificateAuthority::new(&cert, &key)?;
    let proxy_leaf = proxy_ca.for_host(NAME).await?;
    assert_ne!(
        expected_upstream_leaf,
        proxy_leaf.certs[0].as_ref(),
        "test setup must use distinct real-upstream and MITM leaves"
    );

    let mut upstream_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(upstream_leaf.certs.clone(), upstream_leaf.key.clone_key())?;
    upstream_tls.alpn_protocols = vec![ALPN.to_vec()];
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (socket, _) = upstream_listener.accept().await?;
        let mut stream = TlsAcceptor::from(Arc::new(upstream_tls))
            .accept(socket)
            .await?;
        assert_eq!(stream.get_ref().1.server_name(), Some(NAME));
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(ALPN));
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    // The default upstream must be selected through the configured resolver.
    // A and AAAA are looked up concurrently; only A points at the local server.
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let resolver_addr = resolver.local_addr()?;
    let resolver_task = tokio::spawn(async move {
        let mut seen_a = false;
        let mut seen_aaaa = false;
        for _ in 0..2 {
            let mut query = [0u8; 512];
            let (length, peer) = resolver.recv_from(&mut query).await?;
            let query = &query[..length];
            assert_eq!(&query[12..length - 4], b"\x04host\x04skip\x07example\0");
            let qtype = u16::from_be_bytes([query[length - 4], query[length - 3]]);
            let mut response = query.to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            match qtype {
                1 => {
                    assert!(!seen_a);
                    seen_a = true;
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&[
                        0xc0, 0x0c, // Compressed answer name.
                        0, 1, 0, 1, // A, IN.
                        0, 0, 0, 60, // TTL.
                        0, 4, 127, 0, 0, 1, // 127.0.0.1.
                    ]);
                }
                28 => {
                    assert!(!seen_aaaa);
                    seen_aaaa = true;
                }
                other => anyhow::bail!("unexpected DNS query type {other}"),
            }
            resolver.send_to(&response, peer).await?;
        }
        assert!(seen_a && seen_aaaa);
        Ok::<_, anyhow::Error>(())
    });

    // A broader matching route deliberately points elsewhere. The more
    // specific concrete exclusion must win and use NAME plus
    // default_upstream_port as the real upstream instead.
    let route_trap = std::net::TcpListener::bind("127.0.0.1:0")?;
    route_trap.set_nonblocking(true)?;
    let route = Route::parse(&format!(
        "*.skip.example=tcp://127.0.0.1:{}",
        route_trap.local_addr()?.port()
    ))?;
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: upstream_addr.port(),
        resolver: resolver_addr,
        ca: proxy_ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: vec![DomainPattern::parse(NAME)?],
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![ALPN.to_vec()];
    let socket = TcpStream::connect(proxy_addr).await?;
    let mut client = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from(NAME)?, socket)
        .await
        .context("client must negotiate TLS directly with the real upstream")?;
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(ALPN));
    let presented_leaf = client
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .context("real upstream did not present a leaf certificate")?;
    assert_eq!(presented_leaf.as_ref(), expected_upstream_leaf);

    client.write_all(REQUEST).await?;
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    client.shutdown().await?;

    resolver_task.await??;
    upstream_task.await??;
    match route_trap.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!("excluded SNI incorrectly connected to its configured route"),
    }
    proxy_task.abort();
    Ok(())
}

#[test]
fn held_proxy_domain_ignores_reload_until_client_disconnects() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(async { timeout(Duration::from_secs(10), exercise_held_proxy_domain()).await? })
}

async fn exercise_held_proxy_domain() -> Result<()> {
    const NAME: &str = "held.example";

    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let upstream_client = build_upstream_client(None)?;

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let route = Route::parse(&format!(
        "*.example=tcp://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    let listen = "127.0.0.1:0".parse()?;
    let proxy = Proxy::bind(ProxyConfig {
        listen,
        default_upstream_port: upstream_addr.port(),
        resolver: resolver.local_addr()?,
        ca: ca.clone(),
        routes: vec![route.clone()],
        hold_domains: vec![DomainPattern::parse(NAME)?],
        exclude_domains: vec![DomainPattern::parse("example")?],
        default_host: None,
        upstream_client: upstream_client.clone(),
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let config_handle = proxy.config_handle();
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    // Generate a real rustls ClientHello, but keep the underlying socket raw
    // so the test can distinguish silence from either TLS bytes or EOF.
    let mut client_tls = ClientConnection::new(client_config.clone(), ServerName::try_from(NAME)?)?;
    let mut client_hello = Vec::new();
    client_tls.write_tls(&mut client_hello)?;
    assert!(!client_hello.is_empty());

    let mut held_client = TcpStream::connect(proxy_addr).await?;
    held_client.write_all(&client_hello).await?;
    let mut probe = [0u8; 1];
    assert!(
        timeout(Duration::from_millis(200), held_client.read(&mut probe))
            .await
            .is_err(),
        "held connection replied or closed after ClientHello"
    );
    assert!(
        timeout(
            Duration::from_millis(100),
            resolver.recv_from(&mut [0u8; 512])
        )
        .await
        .is_err(),
        "hold lost precedence to proxy.exclude_domains"
    );
    assert!(
        timeout(Duration::from_millis(100), upstream_listener.accept())
            .await
            .is_err(),
        "hold lost precedence to the matching route"
    );

    config_handle.replace(ProxyConfig {
        listen,
        default_upstream_port: upstream_addr.port(),
        resolver: resolver.local_addr()?,
        ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })?;

    assert!(
        timeout(Duration::from_millis(200), held_client.read(&mut probe))
            .await
            .is_err(),
        "reload removal closed or replied to an already-held connection"
    );

    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await?;
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });
    let mut new_client = TlsConnector::from(client_config)
        .connect(
            ServerName::try_from(NAME)?,
            TcpStream::connect(proxy_addr).await?,
        )
        .await
        .context("new connection did not use the reloaded route")?;
    new_client.write_all(REQUEST).await?;
    let mut response = vec![0; RESPONSE.len()];
    new_client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    new_client.shutdown().await?;
    upstream_task.await??;

    // A client write-half close is the first event allowed to end the hold.
    held_client.shutdown().await?;
    let held_eof = timeout(Duration::from_secs(2), held_client.read(&mut probe))
        .await
        .context("held connection remained open after the client half-closed")??;
    assert_eq!(held_eof, 0);

    proxy_task.abort();
    Ok(())
}

#[test]
fn reload_closes_only_connections_whose_effective_policy_changed() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { timeout(Duration::from_secs(10), exercise_selective_reload()).await? })
}

async fn exercise_selective_reload() -> Result<()> {
    const CHANGED_NAME: &str = "changed.reload.example";
    const STABLE_NAME: &str = "stable.reload.example";
    const BEFORE_CHANGED: &[u8] = b"changed before reload";
    const BEFORE_STABLE: &[u8] = b"stable before reload";
    const AFTER_STABLE: &[u8] = b"stable after reload";

    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let upstream_client = build_upstream_client(None)?;

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = upstream_listener.accept().await?;
            connections.push(tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                loop {
                    let count = stream.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    stream.write_all(&buffer[..count]).await?;
                }
                Ok::<_, anyhow::Error>(())
            }));
        }
        for connection in connections {
            connection.await??;
        }
        Ok::<_, anyhow::Error>(())
    });

    let changed_route = Route::parse(&format!(
        "{CHANGED_NAME}=tcp://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    let stable_route = Route::parse(&format!(
        "{STABLE_NAME}=tcp://127.0.0.1:{}",
        upstream_addr.port()
    ))?;
    let listen = "127.0.0.1:0".parse()?;
    let proxy = Proxy::bind(ProxyConfig {
        listen,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca: ca.clone(),
        routes: vec![changed_route, stable_route.clone()],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client: upstream_client.clone(),
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let config_handle = proxy.config_handle();
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let mut changed_client = TlsConnector::from(client_config.clone())
        .connect(
            ServerName::try_from(CHANGED_NAME)?,
            TcpStream::connect(proxy_addr).await?,
        )
        .await?;
    let mut stable_client = TlsConnector::from(client_config)
        .connect(
            ServerName::try_from(STABLE_NAME)?,
            TcpStream::connect(proxy_addr).await?,
        )
        .await?;

    changed_client.write_all(BEFORE_CHANGED).await?;
    let mut changed_echo = vec![0; BEFORE_CHANGED.len()];
    changed_client.read_exact(&mut changed_echo).await?;
    assert_eq!(changed_echo, BEFORE_CHANGED);
    stable_client.write_all(BEFORE_STABLE).await?;
    let mut stable_echo = vec![0; BEFORE_STABLE.len()];
    stable_client.read_exact(&mut stable_echo).await?;
    assert_eq!(stable_echo, BEFORE_STABLE);

    // Only this route's target changes. The other connection's effective plan
    // remains byte-for-byte equal and must survive the same config broadcast.
    let changed_target = TcpListener::bind("127.0.0.1:0").await?;
    let changed_route = Route::parse(&format!(
        "{CHANGED_NAME}=tcp://127.0.0.1:{}",
        changed_target.local_addr()?.port()
    ))?;
    config_handle.replace(ProxyConfig {
        listen,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![changed_route, stable_route],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })?;

    let mut closed_probe = [0u8; 1];
    let closed = timeout(
        Duration::from_secs(2),
        changed_client.read(&mut closed_probe),
    )
    .await
    .context("changed-policy connection remained open after reload")?;
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "changed-policy connection delivered unexpected data instead of closing: {closed:?}"
    );
    drop(changed_client);

    stable_client.write_all(AFTER_STABLE).await?;
    let mut stable_echo = vec![0; AFTER_STABLE.len()];
    stable_client.read_exact(&mut stable_echo).await?;
    assert_eq!(stable_echo, AFTER_STABLE);
    stable_client.shutdown().await?;

    upstream_task.await??;
    proxy_task.abort();
    Ok(())
}

#[test]
fn reload_cancels_passthrough_connection_during_resolution() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        timeout(
            Duration::from_secs(10),
            exercise_setup_phase_reload_cancellation(),
        )
        .await?
    })
}

async fn exercise_setup_phase_reload_cancellation() -> Result<()> {
    const NAME: &str = "pending.reload.example";

    let cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.crt.pem");
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs/test.key.pem");
    let ca = CertificateAuthority::new(&cert, &key)?;
    let upstream_client = build_upstream_client(None)?;
    let real_upstream = TcpListener::bind("127.0.0.1:0").await?;
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;

    let route = Route::parse(&format!(
        "*.reload.example=tcp://127.0.0.1:{}",
        real_upstream.local_addr()?.port()
    ))?;
    let listen = "127.0.0.1:0".parse()?;
    let proxy = Proxy::bind(ProxyConfig {
        listen,
        default_upstream_port: real_upstream.local_addr()?.port(),
        resolver: resolver.local_addr()?,
        ca: ca.clone(),
        routes: vec![route.clone()],
        hold_domains: Vec::new(),
        exclude_domains: vec![DomainPattern::parse(NAME)?],
        default_host: None,
        upstream_client: upstream_client.clone(),
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let config_handle = proxy.config_handle();
    let proxy_task = tokio::spawn(proxy.serve());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(&cert)?)?;
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let client_task = tokio::spawn(async move {
        TlsConnector::from(client_config)
            .connect(
                ServerName::try_from(NAME)?,
                TcpStream::connect(proxy_addr).await?,
            )
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    });

    // The old passthrough plan is now blocked in DNS resolution. Removing the
    // exclusion must cancel it immediately instead of letting that setup finish.
    let mut query = [0u8; 512];
    timeout(Duration::from_secs(2), resolver.recv_from(&mut query))
        .await
        .context("proxy never began passthrough resolution")??;
    assert!(!client_task.is_finished());
    config_handle.replace(ProxyConfig {
        listen,
        default_upstream_port: real_upstream.local_addr()?.port(),
        resolver: resolver.local_addr()?,
        ca,
        routes: vec![route],
        hold_domains: Vec::new(),
        exclude_domains: Vec::new(),
        default_host: None,
        upstream_client,
        capture: None,
        ca_revision: 0,
        upstream_trust_revision: 0,
    })?;

    let client_result = timeout(Duration::from_secs(2), client_task)
        .await
        .context("setup-phase connection survived its policy change")??;
    assert!(
        client_result.is_err(),
        "cancelled passthrough unexpectedly completed TLS"
    );
    assert!(
        timeout(Duration::from_millis(200), real_upstream.accept())
            .await
            .is_err(),
        "old passthrough connected after its policy changed"
    );

    proxy_task.abort();
    Ok(())
}

#[test]
fn dns_redirects_selected_domain_over_udp_and_tcp() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { timeout(Duration::from_secs(5), exercise_dns()).await? })
}

async fn exercise_dns() -> Result<()> {
    // Reserve an unprivileged port, then let the DNS service bind TCP and UDP
    // to the same address as a normal deployment would.
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let dns_task = tokio::spawn(serve_dns(DnsConfig {
        bind: address,
        upstream: "127.0.0.1:9".parse()?,
        answer_v4: Some(Ipv4Addr::LOCALHOST),
        answer_v6: None,
        hijack_all: false,
        domains: vec![
            DomainPattern::parse("test.example")?,
            DomainPattern::parse("*.wild.example")?,
        ],
        exclude_domains: Vec::new(),
    }));

    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in [b"test".as_slice(), b"example".as_slice()] {
        query.push(label.len() as u8);
        query.extend_from_slice(label);
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]); // Root label, A, IN.

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(address).await?;
    let mut response = [0u8; 512];
    let udp_len = loop {
        udp.send(&query).await?;
        if let Ok(Ok(len)) = timeout(Duration::from_millis(100), udp.recv(&mut response)).await {
            break len;
        }
        if dns_task.is_finished() {
            dns_task.await??;
            anyhow::bail!("DNS service ended during startup");
        }
    };
    assert_dns_loopback_answer(&query, &response[..udp_len]);

    let mut tcp = TcpStream::connect(address).await?;
    tcp.write_all(&(query.len() as u16).to_be_bytes()).await?;
    tcp.write_all(&query).await?;
    let mut reply_len = [0u8; 2];
    tcp.read_exact(&mut reply_len).await?;
    let mut reply = vec![0; u16::from_be_bytes(reply_len) as usize];
    tcp.read_exact(&mut reply).await?;
    assert_dns_loopback_answer(&query, &reply);

    let mut wildcard_query = vec![0x12, 0x35, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in [
        b"host".as_slice(),
        b"wild".as_slice(),
        b"example".as_slice(),
    ] {
        wildcard_query.push(label.len() as u8);
        wildcard_query.extend_from_slice(label);
    }
    wildcard_query.extend_from_slice(&[0, 0, 1, 0, 1]);

    let wildcard_udp = UdpSocket::bind("127.0.0.1:0").await?;
    wildcard_udp.connect(address).await?;
    wildcard_udp.send(&wildcard_query).await?;
    let wildcard_len = timeout(Duration::from_secs(1), wildcard_udp.recv(&mut response)).await??;
    assert_dns_loopback_answer(&wildcard_query, &response[..wildcard_len]);

    tcp.write_all(&(wildcard_query.len() as u16).to_be_bytes())
        .await?;
    tcp.write_all(&wildcard_query).await?;
    tcp.read_exact(&mut reply_len).await?;
    let mut wildcard_reply = vec![0; u16::from_be_bytes(reply_len) as usize];
    tcp.read_exact(&mut wildcard_reply).await?;
    assert_dns_loopback_answer(&wildcard_query, &wildcard_reply);

    dns_task.abort();
    Ok(())
}

fn assert_dns_loopback_answer(query: &[u8], response: &[u8]) {
    assert!(response.len() >= query.len() + 16);
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response[2] & 0x80, 0x80); // Response bit.
    assert_eq!(response[3] & 0x0f, 0); // No DNS error.
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
    assert_eq!(
        &response[response.len() - 4..],
        &Ipv4Addr::LOCALHOST.octets()
    );
}
