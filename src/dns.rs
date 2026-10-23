//! A small DNS relay for directing a test device at the TLS interception listener.
//!
//! It deliberately uses the configured upstream resolver instead of the host's
//! resolver, since the latter may itself have been pointed at this service.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::domain::DomainPattern;

const MAX_MESSAGE: usize = u16::MAX as usize;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_REQUESTS: usize = 256;
const LOCAL_TTL: u32 = 60;
static NEXT_QUERY_ID: AtomicU16 = AtomicU16::new(0x5a31);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub answer_v4: Option<Ipv4Addr>,
    pub answer_v6: Option<Ipv6Addr>,
    pub hijack_all: bool,
    /// A plain name matches itself and its subdomains; `*.name` matches only
    /// subdomains, and `*` matches every name.
    pub domains: Vec<DomainPattern>,
    /// Explicit forwarding rules that compete with `domains` in both modes.
    /// These patterns use the same precedence rules as `domains`.
    pub exclude_domains: Vec<DomainPattern>,
}

/// A DNS server whose UDP and TCP listeners stay bound while its query policy
/// can be replaced atomically.
pub struct DnsServer {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    config: watch::Sender<Arc<DnsConfig>>,
}

#[derive(Clone)]
pub struct DnsConfigHandle {
    config: watch::Sender<Arc<DnsConfig>>,
}

pub struct DnsConfigUpdate {
    config: watch::Sender<Arc<DnsConfig>>,
    next: Arc<DnsConfig>,
}

impl DnsConfigUpdate {
    pub fn publish(self) {
        self.config.send_replace(self.next);
    }
}

impl DnsConfigHandle {
    /// Validate and stage a query policy without rebinding the DNS listeners.
    pub fn prepare_replace(&self, config: DnsConfig) -> Result<DnsConfigUpdate> {
        let current = self.config.borrow();
        if config.bind != current.bind {
            bail!(
                "DNS listener address cannot change from {} to {} during reload",
                current.bind,
                config.bind
            );
        }
        drop(current);
        validate_config(&config)?;
        Ok(DnsConfigUpdate {
            config: self.config.clone(),
            next: Arc::new(config),
        })
    }

    /// Publish a new query policy without rebinding the DNS listeners.
    pub fn replace(&self, config: DnsConfig) -> Result<()> {
        self.prepare_replace(config)?.publish();
        Ok(())
    }
}

impl DnsServer {
    pub async fn bind(config: DnsConfig) -> Result<Self> {
        validate_config(&config)?;

        let tcp = TcpListener::bind(config.bind)
            .await
            .with_context(|| format!("binding TCP DNS listener on {}", config.bind))?;
        let actual_bind = tcp
            .local_addr()
            .context("reading TCP DNS listener address")?;
        let udp = Arc::new(
            UdpSocket::bind(actual_bind)
                .await
                .with_context(|| format!("binding UDP DNS listener on {actual_bind}"))?,
        );
        let (config, _) = watch::channel(Arc::new(config));
        Ok(Self { udp, tcp, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp
            .local_addr()
            .context("reading DNS listener address")
    }

    pub fn config_handle(&self) -> DnsConfigHandle {
        DnsConfigHandle {
            config: self.config.clone(),
        }
    }

    pub async fn serve(self) -> Result<()> {
        let udp_config = self.config.subscribe();
        let tcp_config = self.config.subscribe();
        futures::try_join!(
            serve_udp(self.udp, udp_config),
            serve_tcp(self.tcp, tcp_config)
        )?;
        Ok(())
    }
}

/// Serve DNS over UDP and TCP on the same address. Both transports are required
/// because clients retry truncated UDP replies over TCP.
pub async fn serve_dns(config: DnsConfig) -> Result<()> {
    DnsServer::bind(config).await?.serve().await
}

fn validate_config(config: &DnsConfig) -> Result<()> {
    if config.upstream.port() == 0 {
        bail!("DNS upstream port must not be zero");
    }
    if points_to_self(config.bind, config.upstream) {
        bail!("DNS upstream points at this DNS listener");
    }
    Ok(())
}

pub(crate) fn points_to_self(bind: SocketAddr, upstream: SocketAddr) -> bool {
    if bind.port() != upstream.port() {
        return false;
    }
    bind.ip() == upstream.ip()
        || (bind.ip().is_unspecified()
            && bind.is_ipv4() == upstream.is_ipv4()
            && (upstream.ip().is_loopback() || upstream.ip().is_unspecified()))
}

async fn serve_udp(socket: Arc<UdpSocket>, config: watch::Receiver<Arc<DnsConfig>>) -> Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let mut buffer = vec![0; MAX_MESSAGE];
    loop {
        let permit = limit.clone().acquire_owned().await?;
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let query = buffer[..len].to_vec();
        let socket = socket.clone();
        let config = config.borrow().clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(reply) = handle_query(&query, &config, Transport::Udp, peer).await {
                if let Err(error) = socket.send_to(&reply, peer).await {
                    warn!(%peer, %error, "failed to send DNS UDP reply");
                }
            }
        });
    }
}

async fn serve_tcp(listener: TcpListener, config: watch::Receiver<Arc<DnsConfig>>) -> Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    loop {
        let permit = limit.clone().acquire_owned().await?;
        let (stream, peer) = listener.accept().await?;
        debug!(%peer, "accepted DNS TCP client");
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_tcp_client(stream, config, peer).await {
                warn!(%peer, error = %format_args!("{error:#}"), "DNS TCP client failed");
            }
        });
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    config: watch::Receiver<Arc<DnsConfig>>,
    peer: SocketAddr,
) -> Result<()> {
    loop {
        let mut length = [0u8; 2];
        match timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut length)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Ok(()),
        }
        let length = u16::from_be_bytes(length) as usize;
        if length == 0 {
            return Ok(());
        }
        let mut query = vec![0u8; length];
        timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut query))
            .await
            .context("DNS TCP query timed out")??;
        let config = config.borrow().clone();
        if let Some(reply) = handle_query(&query, &config, Transport::Tcp, peer).await {
            let length = (reply.len() as u16).to_be_bytes();
            timeout(DNS_TIMEOUT, async {
                stream.write_all(&length).await?;
                stream.write_all(&reply).await
            })
            .await
            .context("DNS TCP reply timed out")??;
        }
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

async fn handle_query(
    query: &[u8],
    config: &DnsConfig,
    transport: Transport,
    peer: SocketAddr,
) -> Option<Vec<u8>> {
    match classify_query(query, config) {
        QueryAction::Ignore => None,
        QueryAction::Reply(reply) => Some(reply),
        QueryAction::Hijack {
            reply,
            question,
            address,
        } => {
            match address {
                Some(address) => info!(
                    client = %peer,
                    transport = transport.as_str(),
                    name = %question.log_name(),
                    record = %question.record_type(),
                    %address,
                    "hijacked DNS query"
                ),
                None => info!(
                    client = %peer,
                    transport = transport.as_str(),
                    name = %question.log_name(),
                    record = %question.record_type(),
                    "hijacked DNS query with an empty answer"
                ),
            }
            Some(reply)
        }
        QueryAction::Forward(question) => {
            debug!(
                client = %peer,
                name = %question.log_name(),
                record = %question.record_type(),
                transport = transport.as_str(),
                upstream = %config.upstream,
                "forwarding DNS query"
            );
            let reply = match transport {
                Transport::Udp => exchange_udp(query, config.upstream).await,
                Transport::Tcp => exchange_tcp(query, config.upstream).await,
            };
            match reply {
                Ok(reply) if response_matches_request(&reply, query) => Some(reply),
                Ok(_) => {
                    warn!(
                        client = %peer,
                        name = %question.log_name(),
                        record = %question.record_type(),
                        transport = transport.as_str(),
                        upstream = %config.upstream,
                        "DNS upstream returned a mismatched response"
                    );
                    Some(error_response(query, Some(&question), 2))
                }
                Err(error) => {
                    warn!(
                        client = %peer,
                        name = %question.log_name(),
                        record = %question.record_type(),
                        transport = transport.as_str(),
                        upstream = %config.upstream,
                        error = %format_args!("{error:#}"),
                        "DNS upstream query failed"
                    );
                    Some(error_response(query, Some(&question), 2))
                }
            }
        }
    }
}

fn response_matches_request(reply: &[u8], query: &[u8]) -> bool {
    if reply.len() < 12 || query.len() < 12 || reply[..2] != query[..2] {
        return false;
    }
    let query_flags = u16::from_be_bytes([query[2], query[3]]);
    let reply_flags = u16::from_be_bytes([reply[2], reply[3]]);
    if query_flags & 0x8000 != 0
        || reply_flags & 0x8000 == 0
        || (query_flags ^ reply_flags) & 0x7800 != 0
        || query[4..6] != [0, 1]
        || reply[4..6] != [0, 1]
    {
        return false;
    }
    let (Some(requested), Some(answered)) = (parse_question(query), parse_question(reply)) else {
        return false;
    };
    requested.qtype == answered.qtype
        && requested.qclass == answered.qclass
        && requested.labels.len() == answered.labels.len()
        && requested
            .labels
            .iter()
            .zip(answered.labels.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

enum QueryAction {
    Ignore,
    Reply(Vec<u8>),
    Hijack {
        reply: Vec<u8>,
        question: Question,
        address: Option<IpAddr>,
    },
    Forward(Question),
}

#[derive(Debug)]
struct Question {
    labels: Vec<Vec<u8>>,
    qtype: u16,
    qclass: u16,
}

impl Question {
    fn log_name(&self) -> String {
        canonical_name(&self.labels).unwrap_or_else(|| "<invalid>".to_owned())
    }

    fn record_type(&self) -> Cow<'static, str> {
        match self.qtype {
            1 => "A".into(),
            5 => "CNAME".into(),
            28 => "AAAA".into(),
            39 => "DNAME".into(),
            64 => "SVCB".into(),
            65 => "HTTPS".into(),
            255 => "ANY".into(),
            other => format!("TYPE{other}").into(),
        }
    }
}

fn classify_query(query: &[u8], config: &DnsConfig) -> QueryAction {
    if query.len() < 2 {
        return QueryAction::Ignore;
    }
    if query.len() < 12 {
        return QueryAction::Reply(error_response(query, None, 1));
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return QueryAction::Ignore;
    }
    let count = u16::from_be_bytes([query[4], query[5]]);
    if count != 1 {
        return QueryAction::Reply(error_response(query, None, 1));
    }
    let question = match parse_question(query) {
        Some(question) => question,
        None => return QueryAction::Reply(error_response(query, None, 1)),
    };
    // Leave nonstandard opcodes and classes to the actual upstream server.
    if flags & 0x7800 != 0 || question.qclass != 1 {
        return QueryAction::Forward(question);
    }
    if !matches_domain(&question.labels, config) {
        return QueryAction::Forward(question);
    }
    let address = match question.qtype {
        1 => Some(config.answer_v4.map(IpAddr::V4)),
        28 => Some(config.answer_v6.map(IpAddr::V6)),
        // These records can direct clients to another host, QUIC or ECH.
        5 | 39 | 64 | 65 | 255 => Some(None),
        _ => None,
    };
    match address {
        Some(address) => {
            let reply = local_response(query, &question, address);
            QueryAction::Hijack {
                reply,
                question,
                address,
            }
        }
        None => QueryAction::Forward(question),
    }
}

fn matches_domain(labels: &[Vec<u8>], config: &DnsConfig) -> bool {
    let included = config
        .domains
        .iter()
        .filter(|pattern| pattern.matches_wire_labels(labels))
        .max_by_key(|pattern| pattern.specificity());
    let excluded = config
        .exclude_domains
        .iter()
        .filter(|pattern| pattern.matches_wire_labels(labels))
        .max_by_key(|pattern| pattern.specificity());

    match (included, excluded) {
        (Some(included), Some(excluded)) => included.specificity() > excluded.specificity(),
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => config.hijack_all,
    }
}

fn parse_question(message: &[u8]) -> Option<Question> {
    let (labels, end) = decode_name(message, 12)?;
    let tail = message.get(end..end.checked_add(4)?)?;
    Some(Question {
        labels,
        qtype: u16::from_be_bytes([tail[0], tail[1]]),
        qclass: u16::from_be_bytes([tail[2], tail[3]]),
    })
}

/// Decode a potentially compressed DNS name, returning the offset immediately
/// after its encoded form. The visited set rejects pointer loops.
fn decode_name(message: &[u8], start: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut position = start;
    let mut end = None;
    let mut expanded_length = 1usize; // The final root label.
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(position) {
            return None;
        }
        if visited.len() > 128 {
            return None;
        }
        let length = *message.get(position)?;
        match length & 0xc0 {
            0xc0 => {
                let second = *message.get(position.checked_add(1)?)?;
                let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
                end.get_or_insert(position + 2);
                position = pointer;
            }
            0 => {
                position += 1;
                if length == 0 {
                    return Some((labels, end.unwrap_or(position)));
                }
                let stop = position.checked_add(usize::from(length))?;
                let label = message.get(position..stop)?;
                expanded_length = expanded_length.checked_add(1 + label.len())?;
                if expanded_length > 255 {
                    return None;
                }
                labels.push(label.to_vec());
                position = stop;
            }
            _ => return None,
        }
    }
}

fn encode_name(labels: &[Vec<u8>], target: &mut Vec<u8>) {
    for label in labels {
        target.push(label.len() as u8);
        target.extend_from_slice(label);
    }
    target.push(0);
}

fn append_question(question: &Question, target: &mut Vec<u8>) {
    encode_name(&question.labels, target);
    target.extend_from_slice(&question.qtype.to_be_bytes());
    target.extend_from_slice(&question.qclass.to_be_bytes());
}

fn base_flags(query: &[u8], rcode: u16) -> u16 {
    let incoming = if query.len() >= 4 {
        u16::from_be_bytes([query[2], query[3]])
    } else {
        0
    };
    0x8000 | 0x0080 | (incoming & 0x0110) | rcode
}

fn write_header(query: &[u8], flags: u16, questions: u16, answers: u16, target: &mut Vec<u8>) {
    target.extend_from_slice(&query[..2]);
    target.extend_from_slice(&flags.to_be_bytes());
    target.extend_from_slice(&questions.to_be_bytes());
    target.extend_from_slice(&answers.to_be_bytes());
    target.extend_from_slice(&0u16.to_be_bytes());
    target.extend_from_slice(&0u16.to_be_bytes());
}

fn local_response(query: &[u8], question: &Question, address: Option<IpAddr>) -> Vec<u8> {
    let mut response = Vec::with_capacity(300);
    write_header(
        query,
        base_flags(query, 0),
        1,
        u16::from(address.is_some()),
        &mut response,
    );
    append_question(question, &mut response);
    if let Some(address) = address {
        response.extend_from_slice(&[0xc0, 0x0c]); // Name in the rebuilt question.
        let (record_type, bytes): (u16, Vec<u8>) = match address {
            IpAddr::V4(ip) => (1, ip.octets().to_vec()),
            IpAddr::V6(ip) => (28, ip.octets().to_vec()),
        };
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&LOCAL_TTL.to_be_bytes());
        response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        response.extend_from_slice(&bytes);
    }
    response
}

fn error_response(query: &[u8], question: Option<&Question>, rcode: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(300);
    write_header(
        query,
        base_flags(query, rcode),
        u16::from(question.is_some()),
        0,
        &mut response,
    );
    if let Some(question) = question {
        append_question(question, &mut response);
    }
    response
}

async fn exchange_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    timeout(DNS_TIMEOUT, async {
        let local = if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(upstream).await?;
        socket.send(query).await?;
        let mut reply = vec![0; MAX_MESSAGE];
        let len = socket.recv(&mut reply).await?;
        reply.truncate(len);
        Ok::<_, anyhow::Error>(reply)
    })
    .await
    .context("UDP DNS upstream timed out")?
}

async fn exchange_tcp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    timeout(DNS_TIMEOUT, async {
        let mut stream = TcpStream::connect(upstream).await?;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(query).await?;
        let mut length = [0; 2];
        stream.read_exact(&mut length).await?;
        let length = u16::from_be_bytes(length) as usize;
        if length < 12 {
            bail!("DNS upstream returned a short TCP response");
        }
        let mut reply = vec![0; length];
        stream.read_exact(&mut reply).await?;
        Ok::<_, anyhow::Error>(reply)
    })
    .await
    .context("TCP DNS upstream timed out")?
}

/// Resolve a TLS upstream host using only the specified DNS resolver. This
/// prevents a hijacked system resolver from directing the upstream connection
/// straight back into the interception listener.
pub async fn resolve_host(host: &str, port: u16, resolver: SocketAddr) -> Result<Vec<SocketAddr>> {
    let host = host.trim();
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        debug!(%host, %port, "upstream host is an IP address");
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    debug!(%host, %port, %resolver, "resolving upstream host");
    let name = encode_host_name(host)?;
    let (v4, v6) = timeout(RESOLUTION_TIMEOUT, async {
        futures::join!(
            resolve_type(&name, 1, resolver),
            resolve_type(&name, 28, resolver)
        )
    })
    .await
    .with_context(|| format!("DNS resolution timed out for {host}"))?;
    let mut addresses = Vec::new();
    for ips in [&v4, &v6].into_iter().flatten() {
        for ip in ips {
            let socket = SocketAddr::new(*ip, port);
            if !addresses.contains(&socket) {
                addresses.push(socket);
            }
        }
    }
    if !addresses.is_empty() {
        debug!(%host, count = addresses.len(), "resolved upstream host");
        return Ok(addresses);
    }
    match (v4, v6) {
        (Err(v4), Err(v6)) => Err(anyhow!(
            "DNS A and AAAA lookup failed for {host}: {v4}; {v6}"
        )),
        (Err(error), _) | (_, Err(error)) => {
            Err(error).with_context(|| format!("resolving {host}"))
        }
        _ => bail!("DNS resolver returned no A or AAAA records for {host}"),
    }
}

fn encode_host_name(host: &str) -> Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        bail!("invalid DNS hostname");
    }
    let mut wire = Vec::with_capacity(host.len() + 2);
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("invalid DNS hostname label");
        }
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    Ok(wire)
}

async fn resolve_type(name: &[u8], qtype: u16, resolver: SocketAddr) -> Result<Vec<IpAddr>> {
    let mut current_name = name.to_vec();
    let mut seen = HashSet::new();
    for _ in 0..=8 {
        let (labels, _) = decode_name(&current_name, 0).context("invalid lookup name")?;
        let canonical = canonical_name(&labels).context("invalid lookup name")?;
        if !seen.insert(canonical) {
            bail!("DNS resolver returned a CNAME loop");
        }
        let id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut query = Vec::with_capacity(12 + current_name.len() + 4);
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&[0; 6]);
        query.extend_from_slice(&current_name);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        let mut reply = exchange_udp(&query, resolver).await?;
        if !response_matches_request(&reply, &query) {
            bail!("DNS resolver returned a mismatched response");
        }
        if u16::from_be_bytes([reply[2], reply[3]]) & 0x0200 != 0 {
            reply = exchange_tcp(&query, resolver).await?;
            if !response_matches_request(&reply, &query) {
                bail!("DNS resolver returned a mismatched TCP response");
            }
        }
        let parsed = parse_address_response(&reply, &current_name, qtype)?;
        if !parsed.addresses.is_empty() {
            return Ok(parsed.addresses);
        }
        match parsed.followup_name {
            Some(next) => current_name = encode_host_name(&next)?,
            None => return Ok(Vec::new()),
        }
    }
    bail!("DNS resolver returned a CNAME chain longer than eight hops")
}

fn canonical_name(labels: &[Vec<u8>]) -> Option<String> {
    let mut parts = Vec::with_capacity(labels.len());
    for label in labels {
        if !label.is_ascii() || label.contains(&b'.') {
            return None;
        }
        parts.push(String::from_utf8(label.clone()).ok()?.to_ascii_lowercase());
    }
    Some(parts.join("."))
}

struct AddressAnswer {
    addresses: Vec<IpAddr>,
    followup_name: Option<String>,
}

fn parse_address_response(reply: &[u8], query_name: &[u8], qtype: u16) -> Result<AddressAnswer> {
    if reply.len() < 12 {
        bail!("DNS response is too short");
    }
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    let rcode = flags & 0x000f;
    let qdcount = u16::from_be_bytes([reply[4], reply[5]]) as usize;
    let ancount = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    if qdcount != 1 {
        bail!("DNS resolver returned an unexpected question count");
    }
    let (expected, _) = decode_name(query_name, 0).context("invalid lookup name")?;
    let expected = canonical_name(&expected).context("invalid lookup name")?;
    let (labels, mut offset) = decode_name(reply, 12).context("invalid DNS question")?;
    if canonical_name(&labels).as_deref() != Some(expected.as_str()) {
        bail!("DNS resolver returned a different question");
    }
    let question_tail = reply
        .get(offset..offset + 4)
        .context("short DNS question")?;
    if u16::from_be_bytes([question_tail[0], question_tail[1]]) != qtype
        || u16::from_be_bytes([question_tail[2], question_tail[3]]) != 1
    {
        bail!("DNS resolver returned a different query type or class");
    }
    if rcode == 3 {
        return Ok(AddressAnswer {
            addresses: Vec::new(),
            followup_name: None,
        });
    }
    if rcode != 0 {
        bail!("DNS resolver returned RCODE {rcode}");
    }
    offset += 4;
    let mut aliases = HashMap::<String, String>::new();
    let mut records = Vec::<(String, IpAddr)>::new();
    for _ in 0..ancount {
        let (owner_labels, end) = decode_name(reply, offset).context("invalid DNS answer owner")?;
        let owner = canonical_name(&owner_labels);
        let fixed = reply.get(end..end + 10).context("short DNS answer")?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let data_length = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let data_start = end + 10;
        let data_end = data_start
            .checked_add(data_length)
            .context("DNS answer overflow")?;
        let data = reply
            .get(data_start..data_end)
            .context("short DNS answer data")?;
        if class == 1 {
            match (record_type, data) {
                (1, [a, b, c, d]) => {
                    if let Some(owner) = owner {
                        records.push((owner, IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))));
                    }
                }
                (28, bytes) if bytes.len() == 16 => {
                    if let Some(owner) = owner {
                        let mut octets = [0; 16];
                        octets.copy_from_slice(bytes);
                        records.push((owner, IpAddr::V6(Ipv6Addr::from(octets))));
                    }
                }
                (5, _) => {
                    if let Some(owner) = owner {
                        if let Some((target_labels, target_end)) = decode_name(reply, data_start) {
                            if target_end == data_end {
                                if let Some(target) = canonical_name(&target_labels) {
                                    aliases.insert(owner, target);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        offset = data_end;
    }
    let mut valid_names = HashSet::new();
    let mut current = expected.clone();
    for _ in 0..=8 {
        if !valid_names.insert(current.clone()) {
            break;
        }
        match aliases.get(&current) {
            Some(next) => current = next.clone(),
            None => break,
        }
    }
    let addresses = records
        .into_iter()
        .filter(|(owner, ip)| {
            valid_names.contains(owner)
                && matches!((qtype, ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)))
        })
        .map(|(_, ip)| ip)
        .collect();
    Ok(AddressAnswer {
        addresses,
        followup_name: (current != expected).then_some(current),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DnsConfig {
        DnsConfig {
            bind: "127.0.0.1:5300".parse().unwrap(),
            upstream: "127.0.0.1:5301".parse().unwrap(),
            answer_v4: Some(Ipv4Addr::new(192, 0, 2, 44)),
            answer_v6: None,
            hijack_all: false,
            domains: vec![DomainPattern::parse("Example.COM.").unwrap()],
            exclude_domains: Vec::new(),
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&encode_host_name(name).unwrap());
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    async fn exchange_with_tcp(stream: &mut TcpStream, query: &[u8]) -> Vec<u8> {
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(query).await.unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut reply = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    }

    fn assert_v4_answer(reply: &[u8], expected: Ipv4Addr) {
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        assert_eq!(reply.get(reply.len() - 4..), Some(&expected.octets()[..]));
    }

    #[test]
    fn bound_server_applies_reloads_to_udp_and_existing_tcp_clients() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            timeout(Duration::from_secs(2), async {
                let mut initial = config();
                initial.bind = "127.0.0.1:0".parse().unwrap();
                let server = DnsServer::bind(initial.clone()).await.unwrap();
                let address = server.local_addr().unwrap();
                let handle = server.config_handle();
                let server_task = tokio::spawn(server.serve());

                let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let request = query("example.com", 1);
                udp.send_to(&request, address).await.unwrap();
                let mut packet = [0; 512];
                let (length, _) = udp.recv_from(&mut packet).await.unwrap();
                assert_v4_answer(&packet[..length], Ipv4Addr::new(192, 0, 2, 44));

                let mut tcp = TcpStream::connect(address).await.unwrap();
                let reply = exchange_with_tcp(&mut tcp, &request).await;
                assert_v4_answer(&reply, Ipv4Addr::new(192, 0, 2, 44));

                let mut replacement = initial.clone();
                replacement.answer_v4 = Some(Ipv4Addr::new(198, 51, 100, 27));
                handle.replace(replacement).unwrap();

                udp.send_to(&request, address).await.unwrap();
                let (length, _) = udp.recv_from(&mut packet).await.unwrap();
                assert_v4_answer(&packet[..length], Ipv4Addr::new(198, 51, 100, 27));

                let reply = exchange_with_tcp(&mut tcp, &request).await;
                assert_v4_answer(&reply, Ipv4Addr::new(198, 51, 100, 27));

                let mut moved = initial;
                moved.bind = "127.0.0.1:5302".parse().unwrap();
                let error = handle.replace(moved).unwrap_err();
                assert!(error
                    .to_string()
                    .contains("DNS listener address cannot change"));

                server_task.abort();
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn formats_known_and_unknown_record_types() {
        let known = parse_question(&query("example.com", 1)).unwrap();
        let unknown = parse_question(&query("example.com", 65400)).unwrap();
        assert_eq!(known.record_type(), "A");
        assert_eq!(unknown.record_type(), "TYPE65400");
    }

    #[test]
    fn forwarded_reply_requires_the_original_question_and_opcode() {
        let request = query("Example.ORG", 1);
        let mut reply = request.clone();
        reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        reply[13] = b'e'; // DNS names are case-insensitive.
        assert!(response_matches_request(&reply, &request));

        let mut mismatched = reply.clone();
        mismatched[14] = b'z';
        assert!(!response_matches_request(&mismatched, &request));

        let mut mismatched = reply.clone();
        let type_offset = mismatched.len() - 4;
        mismatched[type_offset + 1] = 28;
        assert!(!response_matches_request(&mismatched, &request));

        let mut mismatched = reply.clone();
        let class_offset = mismatched.len() - 2;
        mismatched[class_offset + 1] = 3;
        assert!(!response_matches_request(&mismatched, &request));

        let mut mismatched = reply.clone();
        mismatched[2] = 0x89; // Different DNS opcode.
        assert!(!response_matches_request(&mismatched, &request));

        let mut mismatched = reply.clone();
        mismatched[5] = 0; // Missing question.
        assert!(!response_matches_request(&mismatched, &request));

        let mut mismatched = reply.clone();
        mismatched[12..14].copy_from_slice(&[0xc0, 0x0c]); // Compression loop.
        assert!(!response_matches_request(&mismatched, &request));
    }

    #[test]
    fn forwarded_mismatched_reply_becomes_servfail() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            timeout(Duration::from_secs(2), async {
                let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let mut config = config();
                config.upstream = resolver.local_addr().unwrap();
                let resolver_task = tokio::spawn(async move {
                    for mismatch in [true, false] {
                        let mut packet = [0u8; 512];
                        let (length, peer) = resolver.recv_from(&mut packet).await.unwrap();
                        let mut reply = packet[..length].to_vec();
                        reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                        if mismatch {
                            let type_offset = reply.len() - 4;
                            reply[type_offset + 1] = 28;
                        }
                        resolver.send_to(&reply, peer).await.unwrap();
                    }
                });

                let request = query("other.example.org", 1);
                let client = "127.0.0.1:12345".parse().unwrap();
                let rejected = handle_query(&request, &config, Transport::Udp, client)
                    .await
                    .unwrap();
                assert_eq!(rejected[3] & 0x0f, 2); // SERVFAIL.
                let accepted = handle_query(&request, &config, Transport::Udp, client)
                    .await
                    .unwrap();
                assert_eq!(accepted[3] & 0x0f, 0);
                assert!(response_matches_request(&accepted, &request));
                resolver_task.await.unwrap();
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn label_boundary_and_case_insensitive_match() {
        let cfg = config();
        assert!(matches!(
            classify_query(&query("EXAMPLE.com", 1), &cfg),
            QueryAction::Hijack { .. }
        ));
        assert!(matches!(
            classify_query(&query("sub.example.com", 1), &cfg),
            QueryAction::Hijack { .. }
        ));
        assert!(matches!(
            classify_query(&query("notexample.com", 1), &cfg),
            QueryAction::Forward(_)
        ));
    }

    #[test]
    fn wildcard_domain_matches_proper_subdomains_only() {
        let mut cfg = config();
        cfg.domains = vec![DomainPattern::parse("*.Example.COM.").unwrap()];
        for name in ["a.example.com", "b.a.EXAMPLE.com"] {
            assert!(matches!(
                classify_query(&query(name, 1), &cfg),
                QueryAction::Hijack { .. }
            ));
        }
        for name in ["example.com", "notexample.com", "a.example.com.evil"] {
            assert!(matches!(
                classify_query(&query(name, 1), &cfg),
                QueryAction::Forward(_)
            ));
        }
    }

    #[test]
    fn star_matches_all_names() {
        let mut cfg = config();
        cfg.domains = vec![DomainPattern::parse("*").unwrap()];
        for name in ["example.com", "other.test", "a.b.example.org"] {
            assert!(matches!(
                classify_query(&query(name, 1), &cfg),
                QueryAction::Hijack { .. }
            ));
        }
    }

    #[test]
    fn all_mode_excludes_domains_with_normal_matching_rules() {
        let mut cfg = config();
        cfg.hijack_all = true;
        cfg.domains.clear();
        cfg.exclude_domains = vec![
            DomainPattern::parse("Example.COM.").unwrap(),
            DomainPattern::parse("*.wild.example").unwrap(),
        ];

        for name in [
            "example.com",
            "a.EXAMPLE.com",
            "host.wild.example",
            "nested.host.wild.example",
        ] {
            assert!(matches!(
                classify_query(&query(name, 1), &cfg),
                QueryAction::Forward(_)
            ));
        }
        for name in [
            "notexample.com",
            "example.com.evil",
            "wild.example",
            "other.test",
        ] {
            assert!(matches!(
                classify_query(&query(name, 1), &cfg),
                QueryAction::Hijack { .. }
            ));
        }

        cfg.hijack_all = false;
        cfg.domains = vec![DomainPattern::parse("example.com").unwrap()];
        cfg.exclude_domains.clear();
        assert!(matches!(
            classify_query(&query("example.com", 1), &cfg),
            QueryAction::Hijack { .. }
        ));
    }

    #[test]
    fn star_exclusion_forwards_every_name_in_all_mode() {
        let mut cfg = config();
        cfg.hijack_all = true;
        cfg.domains.clear();
        cfg.exclude_domains = vec![DomainPattern::parse("*").unwrap()];
        for name in ["example.com", "other.test", "a.b.example.org"] {
            assert!(matches!(
                classify_query(&query(name, 1), &cfg),
                QueryAction::Forward(_)
            ));
        }
    }

    #[test]
    fn domain_groups_compete_by_specificity_in_both_modes() {
        for hijack_all in [false, true] {
            let mut cfg = config();
            cfg.hijack_all = hijack_all;
            cfg.domains = vec![DomainPattern::parse("api.example.com").unwrap()];
            cfg.exclude_domains = vec![DomainPattern::parse("*.example.com").unwrap()];

            assert!(matches!(
                classify_query(&query("api.example.com", 1), &cfg),
                QueryAction::Hijack { .. }
            ));
            assert!(matches!(
                classify_query(&query("deep.api.example.com", 1), &cfg),
                QueryAction::Hijack { .. }
            ));
            assert!(matches!(
                classify_query(&query("other.example.com", 1), &cfg),
                QueryAction::Forward(_)
            ));
            assert_eq!(
                matches!(
                    classify_query(&query("unmatched.test", 1), &cfg),
                    QueryAction::Hijack { .. }
                ),
                hijack_all
            );

            std::mem::swap(&mut cfg.domains, &mut cfg.exclude_domains);
            assert!(matches!(
                classify_query(&query("api.example.com", 1), &cfg),
                QueryAction::Forward(_)
            ));
            assert!(matches!(
                classify_query(&query("other.example.com", 1), &cfg),
                QueryAction::Hijack { .. }
            ));
        }
    }

    #[test]
    fn plain_pattern_beats_same_base_wildcard_in_both_modes() {
        for hijack_all in [false, true] {
            let mut cfg = config();
            cfg.hijack_all = hijack_all;
            cfg.domains = vec![DomainPattern::parse("example.com").unwrap()];
            cfg.exclude_domains = vec![DomainPattern::parse("*.example.com").unwrap()];

            assert!(matches!(
                classify_query(&query("host.example.com", 1), &cfg),
                QueryAction::Hijack { .. }
            ));

            std::mem::swap(&mut cfg.domains, &mut cfg.exclude_domains);
            assert!(matches!(
                classify_query(&query("host.example.com", 1), &cfg),
                QueryAction::Forward(_)
            ));
        }
    }

    #[test]
    fn deeper_wildcard_beats_broader_plain_pattern_in_both_modes() {
        for hijack_all in [false, true] {
            let mut cfg = config();
            cfg.hijack_all = hijack_all;
            cfg.domains = vec![DomainPattern::parse("example.com").unwrap()];
            cfg.exclude_domains = vec![DomainPattern::parse("*.api.example.com").unwrap()];

            assert!(matches!(
                classify_query(&query("host.api.example.com", 1), &cfg),
                QueryAction::Forward(_)
            ));

            std::mem::swap(&mut cfg.domains, &mut cfg.exclude_domains);
            assert!(matches!(
                classify_query(&query("host.api.example.com", 1), &cfg),
                QueryAction::Hijack { .. }
            ));
        }
    }

    #[test]
    fn rewrites_address_and_suppresses_bypass_records() {
        let cfg = config();
        let a = match classify_query(&query("a.example.com", 1), &cfg) {
            QueryAction::Hijack { reply, .. } => reply,
            _ => panic!("expected local answer"),
        };
        assert_eq!(&a[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1);
        assert!(a.ends_with(&[192, 0, 2, 44]));
        for kind in [5, 28, 39, 64, 65, 255] {
            let answer = match classify_query(&query("a.example.com", kind), &cfg) {
                QueryAction::Hijack { reply, .. } => reply,
                _ => panic!("expected local empty answer"),
            };
            assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 0);
            assert_eq!(u16::from_be_bytes([answer[2], answer[3]]) & 0xf, 0);
        }
    }

    #[test]
    fn rejects_multi_question_and_compression_loop() {
        let cfg = config();
        let mut packet = query("example.com", 1);
        packet[5] = 2;
        let response = match classify_query(&packet, &cfg) {
            QueryAction::Reply(packet) => packet,
            _ => panic!("expected FORMERR"),
        };
        assert_eq!(response[3] & 0x0f, 1);
        let mut looped = vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(decode_name(&looped, 12).is_none());
        assert!(matches!(
            classify_query(&looped, &cfg),
            QueryAction::Reply(_)
        ));
    }

    #[test]
    fn compressed_question_is_rebuilt_with_valid_answer_pointer() {
        let cfg = config();
        let mut packet = query("example.com", 1);
        let name = encode_host_name("example.com").unwrap();
        packet.truncate(12);
        packet.extend_from_slice(&[0xc0, 0x12, 0, 1, 0, 1]);
        packet.extend_from_slice(&name);
        let answer = match classify_query(&packet, &cfg) {
            QueryAction::Hijack { reply, .. } => reply,
            _ => panic!("expected local answer"),
        };
        let (labels, end) = decode_name(&answer, 12).unwrap();
        assert_eq!(canonical_name(&labels).as_deref(), Some("example.com"));
        let (answer_labels, _) = decode_name(&answer, end + 4).unwrap();
        assert_eq!(labels, answer_labels);
    }

    #[test]
    fn parses_cname_chain_without_accepting_unrelated_addresses() {
        let q = query("www.example.com", 1);
        let mut reply = q.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 3;
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30]);
        let alias = encode_host_name("target.example.com").unwrap();
        reply.extend_from_slice(&(alias.len() as u16).to_be_bytes());
        reply.extend_from_slice(&alias);
        reply.extend_from_slice(&encode_host_name("target.example.com").unwrap());
        reply.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 9]);
        reply.extend_from_slice(&encode_host_name("unrelated.example.com").unwrap());
        reply.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 1]);
        let answer =
            parse_address_response(&reply, &encode_host_name("www.example.com").unwrap(), 1)
                .unwrap();
        assert_eq!(
            answer.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
        );
        assert_eq!(answer.followup_name.as_deref(), Some("target.example.com"));
    }

    #[test]
    fn guards_against_local_forwarding_loop() {
        assert!(points_to_self(
            "0.0.0.0:53".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap()
        ));
        assert!(!points_to_self(
            "127.0.0.1:5300".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap()
        ));
        assert!(!points_to_self(
            "0.0.0.0:53".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap()
        ));
    }
}
