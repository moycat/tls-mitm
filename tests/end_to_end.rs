use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tls_mitm::capture::start_capture;
use tls_mitm::cert::CertificateAuthority;
use tls_mitm::dns::{serve_dns, DnsConfig};
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

    let mut route = Route::parse("test.example=tls://127.0.0.1")?;
    route.port = Some(upstream_addr.port());
    route.verify = false;
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?, // Numeric route needs no lookup.
        ca,
        routes: vec![route],
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: Some(capture),
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

    let mut route = Route::parse("test.example=tcp://127.0.0.1")?;
    route.port = Some(upstream_addr.port());
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![route],
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
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

    let mut route = Route::parse("test.example=tcp://127.0.0.1")?;
    route.port = Some(upstream_addr.port());
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![route],
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
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

    let mut route = Route::parse("test.example=tls://127.0.0.1")?;
    route.port = Some(upstream_addr.port());
    assert!(route.verify);
    let proxy = Proxy::bind(ProxyConfig {
        listen: "127.0.0.1:0".parse()?,
        default_upstream_port: 443,
        resolver: "127.0.0.1:9".parse()?,
        ca,
        routes: vec![route],
        default_host: None,
        upstream_client: build_upstream_client(None)?,
        capture: None,
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
        default_host: None,
        upstream_client: build_upstream_client(Some(&cert))?,
        capture: None,
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
        domains: vec!["test.example".to_owned(), "*.wild.example".to_owned()],
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
