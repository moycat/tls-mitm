//! Live PCAP output for decrypted application data.
//!
//! Each TCP viewer and output file receives classic PCAP with DLT_RAW packets.
//! The TCP conversations in that stream are synthetic: they carry plaintext on
//! the client's original source address and the proxy's local destination
//! address.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self as std_mpsc, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task::JoinHandle;

const PCAP_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, // little-endian classic PCAP magic
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0, 0, 0, 0, // time zone
    0, 0, 0, 0, // timestamp accuracy
    0xff, 0xff, 0x00, 0x00, // snaplen: 65535
    0x65, 0x00, 0x00, 0x00, // DLT_RAW: 101
];
const MAX_TCP_PAYLOAD: usize = 16 * 1024;
const VIEWER_QUEUE_SIZE: usize = 128;
const OUTPUT_QUEUE_SIZE: usize = 128;
const OUTPUT_RETRY_DELAY: Duration = Duration::from_millis(100);
const FIFO_WRITE_RETRY_DELAY: Duration = Duration::from_millis(10);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

const SYN: u8 = 0x02;
const FIN: u8 = 0x01;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// Broadcast decrypted traffic as PCAP-over-TCP and/or to a file or FIFO.
pub struct CaptureHub {
    output: Arc<CaptureOutput>,
    local_addr: Option<SocketAddr>,
    map_port: Option<u16>,
    next_flow_id: AtomicU32,
    listener_task: Mutex<Option<JoinHandle<()>>>,
    output_stop: Option<Arc<AtomicBool>>,
    output_task: Mutex<Option<thread::JoinHandle<()>>>,
}

struct CaptureOutput {
    viewers: Mutex<Vec<tokio_mpsc::Sender<Arc<[u8]>>>>,
    file: Option<SyncSender<Arc<[u8]>>>,
    slow_viewers: AtomicU64,
    file_queue_drops: AtomicU64,
    file_disconnect_drops: AtomicU64,
}

enum OutputTarget {
    Regular(File, PathBuf),
    Fifo(PathBuf),
}

/// Start PCAP outputs. TCP viewers each receive a new global header. A normal
/// output file is replaced at startup; a pre-existing FIFO waits for readers.
pub async fn start_capture(
    bind: Option<SocketAddr>,
    map_port: Option<u16>,
    output: Option<PathBuf>,
) -> anyhow::Result<Arc<CaptureHub>> {
    anyhow::ensure!(
        bind.is_some() || output.is_some(),
        "capture needs listen or output"
    );
    anyhow::ensure!(map_port != Some(0), "capture.map_port must be nonzero");
    let listener = if let Some(bind) = bind {
        Some(TcpListener::bind(bind).await?)
    } else {
        None
    };
    let local_addr = listener.as_ref().map(TcpListener::local_addr).transpose()?;
    let target = output.map(prepare_output).transpose()?;
    let (file, output_stop, output_task) = if let Some(target) = target {
        let (sender, receiver) = std_mpsc::sync_channel(OUTPUT_QUEUE_SIZE);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let task = thread::Builder::new()
            .name("pcap-output".into())
            .spawn(move || output_worker(target, receiver, worker_stop))?;
        (Some(sender), Some(stop), Some(task))
    } else {
        (None, None, None)
    };
    let hub = Arc::new(CaptureHub {
        output: Arc::new(CaptureOutput {
            viewers: Mutex::new(Vec::new()),
            file,
            slow_viewers: AtomicU64::new(0),
            file_queue_drops: AtomicU64::new(0),
            file_disconnect_drops: AtomicU64::new(0),
        }),
        local_addr,
        map_port,
        next_flow_id: AtomicU32::new(1),
        listener_task: Mutex::new(None),
        output_stop,
        output_task: Mutex::new(output_task),
    });

    if let Some(listener) = listener {
        let listener_address = listener.local_addr()?;
        let weak_hub = Arc::downgrade(&hub);
        let task = tokio::spawn(async move {
            let mut accept_errors = 0u64;
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(accepted) => {
                        accept_errors = 0;
                        accepted
                    }
                    Err(error) => {
                        accept_errors = accept_errors.saturating_add(1);
                        if accept_errors.is_power_of_two() {
                            eprintln!(
                                "PCAP TCP listener {listener_address}: accept failed ({accept_errors} consecutive errors): {error}"
                            );
                        }
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                        continue;
                    }
                };
                let Some(hub) = weak_hub.upgrade() else {
                    break;
                };
                let (sender, mut receiver) = tokio_mpsc::channel(VIEWER_QUEUE_SIZE);
                lock(&hub.output.viewers).push(sender);
                tokio::spawn(async move {
                    if !matches!(
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            socket.write_all(&PCAP_HEADER)
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                    while let Some(record) = receiver.recv().await {
                        if !matches!(
                            tokio::time::timeout(Duration::from_secs(5), socket.write_all(&record))
                                .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                });
            }
        });
        *lock(&hub.listener_task) = Some(task);
    }
    Ok(hub)
}

fn prepare_output(path: PathBuf) -> anyhow::Result<OutputTarget> {
    match fs::metadata(&path) {
        Ok(metadata) if metadata.file_type().is_fifo() => Ok(OutputTarget::Fifo(path)),
        Ok(metadata) if metadata.is_file() => create_regular_output(path),
        Ok(_) => anyhow::bail!(
            "capture.output is not a regular file or FIFO: {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_regular_output(path),
        Err(error) => Err(error.into()),
    }
}

fn create_regular_output(path: PathBuf) -> anyhow::Result<OutputTarget> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    // Existing files may have broader permissions. Restrict them before any
    // decrypted traffic is written, then replace their previous contents.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.set_len(0)?;
    file.write_all(&PCAP_HEADER)?;
    Ok(OutputTarget::Regular(file, path))
}

fn output_worker(target: OutputTarget, receiver: Receiver<Arc<[u8]>>, stop: Arc<AtomicBool>) {
    match target {
        OutputTarget::Regular(mut file, path) => {
            loop {
                match receiver.recv_timeout(OUTPUT_RETRY_DELAY) {
                    Ok(record) => {
                        if let Err(error) = file.write_all(&record) {
                            eprintln!("capture output {}: {error}", path.display());
                            break;
                        }
                    }
                    Err(std_mpsc::RecvTimeoutError::Timeout) if stop.load(Ordering::Relaxed) => {
                        break;
                    }
                    Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if stop.load(Ordering::Relaxed) {
                    // Flush the already queued records, without waiting for
                    // flows that might outlive the hub.
                    while let Ok(record) = receiver.try_recv() {
                        if file.write_all(&record).is_err() {
                            break;
                        }
                    }
                    break;
                }
            }
            if let Err(error) = file.flush() {
                eprintln!("capture output {}: {error}", path.display());
            }
        }
        OutputTarget::Fifo(path) => output_fifo(path, receiver, stop),
    }
}

fn output_fifo(path: PathBuf, receiver: Receiver<Arc<[u8]>>, stop: Arc<AtomicBool>) {
    let mut writer = None;
    let mut open_failures = 0u64;
    let mut write_failures = 0u64;
    let mut disconnected_readers = 0u64;
    let mut dropped_records = 0u64;
    while !stop.load(Ordering::Relaxed) {
        if writer.as_ref().is_some_and(fifo_reader_gone) {
            writer = None;
            log_fifo_disconnect(&path, &mut disconnected_readers);
        }
        if writer.is_none() {
            // A FIFO opened for writing with O_NONBLOCK fails immediately when
            // there is no reader; keep retrying without holding up the proxy.
            match OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)
            {
                Ok(mut file) => match file.metadata() {
                    Ok(metadata) if metadata.file_type().is_fifo() => {
                        match write_fifo(&mut file, &PCAP_HEADER, &stop) {
                            Ok(()) => {
                                open_failures = 0;
                                write_failures = 0;
                                writer = Some(file);
                            }
                            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                                log_fifo_disconnect(&path, &mut disconnected_readers);
                            }
                            Err(_) if stop.load(Ordering::Relaxed) => break,
                            Err(error) => {
                                log_fifo_error(
                                    &path,
                                    "write PCAP header",
                                    &error,
                                    &mut write_failures,
                                );
                            }
                        }
                    }
                    Ok(_) => log_fifo_error(
                        &path,
                        "inspect output path",
                        &io::Error::new(io::ErrorKind::InvalidData, "path is no longer a FIFO"),
                        &mut open_failures,
                    ),
                    Err(error) => {
                        log_fifo_error(&path, "inspect FIFO", &error, &mut open_failures);
                    }
                },
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                    // No reader is an expected state for a nonblocking FIFO.
                }
                Err(error) => {
                    log_fifo_error(&path, "open FIFO", &error, &mut open_failures);
                }
            }
        }

        match receiver.recv_timeout(OUTPUT_RETRY_DELAY) {
            Ok(record) => {
                if let Some(file) = &mut writer {
                    if fifo_reader_gone(file) {
                        log_fifo_disconnect(&path, &mut disconnected_readers);
                        log_fifo_drop(&path, &mut dropped_records);
                        writer = None;
                    } else if let Err(error) = write_fifo(file, &record, &stop) {
                        if error.kind() == io::ErrorKind::BrokenPipe {
                            log_fifo_disconnect(&path, &mut disconnected_readers);
                        } else if !stop.load(Ordering::Relaxed) {
                            log_fifo_error(&path, "write PCAP record", &error, &mut write_failures);
                        }
                        log_fifo_drop(&path, &mut dropped_records);
                        // A later reader gets a fresh PCAP header.
                        writer = None;
                    }
                } else {
                    log_fifo_drop(&path, &mut dropped_records);
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn log_fifo_error(path: &Path, operation: &str, error: &io::Error, count: &mut u64) {
    *count = count.saturating_add(1);
    if count.is_power_of_two() {
        eprintln!(
            "capture FIFO {}: {operation} failed: {error} ({count} occurrences)",
            path.display()
        );
    }
}

fn log_fifo_disconnect(path: &Path, count: &mut u64) {
    *count = count.saturating_add(1);
    if count.is_power_of_two() {
        eprintln!(
            "capture FIFO {}: reader disconnected ({count} occurrences)",
            path.display()
        );
    }
}

fn log_fifo_drop(path: &Path, count: &mut u64) {
    *count = count.saturating_add(1);
    if count.is_power_of_two() {
        eprintln!(
            "capture FIFO {}: dropped PCAP records ({count} total)",
            path.display()
        );
    }
}

fn fifo_reader_gone(file: &File) -> bool {
    let mut descriptor = libc::pollfd {
        fd: file.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    // SAFETY: poll receives a valid pointer to one live PollFd and is called
    // with nfds=1. Its zero timeout only queries current descriptor state.
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    result > 0 && descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0
}

fn write_fifo(file: &mut File, mut bytes: &[u8], stop: &AtomicBool) -> io::Result<()> {
    while !bytes.is_empty() {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "capture stopped",
            ));
        }
        match file.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(FIFO_WRITE_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl CaptureHub {
    /// The actual TCP listener address, if enabled.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Start a synthetic TCP conversation for a decrypted TLS connection.
    /// `client` and `local` are the accepted socket's peer and local addresses.
    pub fn flow(&self, client: SocketAddr, local: SocketAddr) -> CaptureFlow {
        let id = self.next_flow_id.fetch_add(1, Ordering::Relaxed);
        let ips = match (client.ip(), local.ip()) {
            (IpAddr::V4(c), IpAddr::V4(s)) => IpPair::V4(c, s),
            (IpAddr::V6(c), IpAddr::V6(s)) => IpPair::V6(c, s),
            // A raw IP packet cannot contain one IPv4 and one IPv6 endpoint.
            // Preserve the addresses by representing an IPv4 endpoint as an
            // IPv4-mapped IPv6 address if callers provide a mixed-family pair.
            (IpAddr::V4(c), IpAddr::V6(s)) => IpPair::V6(c.to_ipv6_mapped(), s),
            (IpAddr::V6(c), IpAddr::V4(s)) => IpPair::V6(c, s.to_ipv6_mapped()),
        };
        let client_isn = id.wrapping_mul(0x9e37_79b9).wrapping_add(1);
        let server_isn = id.wrapping_mul(0x7f4a_7c15).wrapping_add(1);
        let mut state = FlowState {
            ips,
            client_port: client.port(),
            server_port: self.map_port.unwrap_or(local.port()),
            client_seq: client_isn,
            server_seq: server_isn,
            ip_id: id as u16,
            closed: false,
        };

        state.emit(&self.output, Direction::Client, SYN, &[]);
        state.client_seq = state.client_seq.wrapping_add(1);
        state.emit(&self.output, Direction::Server, SYN | ACK, &[]);
        state.server_seq = state.server_seq.wrapping_add(1);
        state.emit(&self.output, Direction::Client, ACK, &[]);

        CaptureFlow {
            output: Arc::clone(&self.output),
            state: Mutex::new(state),
        }
    }
}

impl CaptureOutput {
    fn broadcast(&self, packet: &[u8]) {
        let mut viewers = lock(&self.viewers);
        if viewers.is_empty() && self.file.is_none() {
            return;
        }
        let record: Arc<[u8]> = pcap_record(packet).into();
        // A full queue means the viewer cannot keep up. Disconnect it so it
        // cannot hold memory or delay the intercepted connection.
        let mut slow_viewers = 0u64;
        viewers.retain(|viewer| match viewer.try_send(Arc::clone(&record)) {
            Ok(()) => true,
            Err(tokio_mpsc::error::TrySendError::Full(_)) => {
                slow_viewers += 1;
                false
            }
            Err(tokio_mpsc::error::TrySendError::Closed(_)) => false,
        });
        drop(viewers);
        if slow_viewers > 0 {
            let previous = self.slow_viewers.fetch_add(slow_viewers, Ordering::Relaxed);
            let total = previous.saturating_add(slow_viewers);
            if previous == 0 || previous.leading_zeros() != total.leading_zeros() {
                eprintln!("capture TCP viewer queue full: disconnected {total} slow viewers");
            }
        }
        if let Some(file) = &self.file {
            // The disk/FIFO writer is independent of the proxy. An output that
            // cannot keep up drops records once its bounded queue fills.
            if let Err(error) = file.try_send(record) {
                let (reason, counter) = match error {
                    std_mpsc::TrySendError::Full(_) => ("queue full", &self.file_queue_drops),
                    std_mpsc::TrySendError::Disconnected(_) => {
                        ("writer stopped", &self.file_disconnect_drops)
                    }
                };
                let total = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                if total.is_power_of_two() {
                    eprintln!("capture output {reason}: dropped {total} PCAP records");
                }
            }
        }
    }
}

impl Drop for CaptureHub {
    fn drop(&mut self) {
        if let Some(stop) = &self.output_stop {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(task) = self
            .listener_task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
        // The file writer runs on its own thread. Dropping the JoinHandle
        // detaches it; disk/FIFO I/O cannot hold up proxy shutdown.
        self.output_task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

/// One decrypted, bidirectional stream represented as synthetic TCP packets.
pub struct CaptureFlow {
    output: Arc<CaptureOutput>,
    state: Mutex<FlowState>,
}

impl CaptureFlow {
    pub fn client_to_server(&self, bytes: &[u8]) {
        self.data(Direction::Client, bytes);
    }

    pub fn server_to_client(&self, bytes: &[u8]) {
        self.data(Direction::Server, bytes);
    }

    fn data(&self, direction: Direction, bytes: &[u8]) {
        let mut state = lock(&self.state);
        if state.closed {
            return;
        }
        for chunk in bytes.chunks(MAX_TCP_PAYLOAD) {
            state.emit(&self.output, direction, PSH | ACK, chunk);
            match direction {
                Direction::Client => {
                    state.client_seq = state.client_seq.wrapping_add(chunk.len() as u32);
                    state.emit(&self.output, Direction::Server, ACK, &[]);
                }
                Direction::Server => {
                    state.server_seq = state.server_seq.wrapping_add(chunk.len() as u32);
                    state.emit(&self.output, Direction::Client, ACK, &[]);
                }
            }
        }
    }

    /// Emit a normal TCP close. Safe to call more than once.
    pub fn close(&self) {
        let mut state = lock(&self.state);
        if state.closed {
            return;
        }
        state.closed = true;
        state.emit(&self.output, Direction::Client, FIN | ACK, &[]);
        state.client_seq = state.client_seq.wrapping_add(1);
        state.emit(&self.output, Direction::Server, ACK, &[]);
        state.emit(&self.output, Direction::Server, FIN | ACK, &[]);
        state.server_seq = state.server_seq.wrapping_add(1);
        state.emit(&self.output, Direction::Client, ACK, &[]);
    }
}

impl Drop for CaptureFlow {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Client,
    Server,
}

#[derive(Clone, Copy)]
enum IpPair {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

struct FlowState {
    ips: IpPair,
    client_port: u16,
    server_port: u16,
    client_seq: u32,
    server_seq: u32,
    ip_id: u16,
    closed: bool,
}

impl FlowState {
    fn emit(&mut self, output: &CaptureOutput, direction: Direction, flags: u8, payload: &[u8]) {
        let (src_port, dst_port, seq, ack) = match direction {
            Direction::Client => (
                self.client_port,
                self.server_port,
                self.client_seq,
                self.server_seq,
            ),
            Direction::Server => (
                self.server_port,
                self.client_port,
                self.server_seq,
                self.client_seq,
            ),
        };
        let packet = ip_tcp_packet(
            self.ips,
            direction,
            src_port,
            dst_port,
            seq,
            if flags & ACK != 0 { ack } else { 0 },
            flags,
            self.ip_id,
            payload,
        );
        self.ip_id = self.ip_id.wrapping_add(1);
        output.broadcast(&packet);
    }
}

#[allow(clippy::too_many_arguments)]
fn ip_tcp_packet(
    ips: IpPair,
    direction: Direction,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = vec![0u8; 20 + payload.len()];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // five 32-bit words, no options
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    tcp[20..].copy_from_slice(payload);

    match ips {
        IpPair::V4(client, server) => {
            let (src, dst) = match direction {
                Direction::Client => (client, server),
                Direction::Server => (server, client),
            };
            let mut pseudo = Vec::with_capacity(12 + tcp.len());
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(&tcp);
            tcp[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());

            let packet_len = 20 + tcp.len();
            let mut packet = vec![0u8; packet_len];
            packet[0] = 0x45; // IPv4, five 32-bit words
            packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
            packet[8] = 64;
            packet[9] = 6; // TCP
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            let header_checksum = checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            packet[20..].copy_from_slice(&tcp);
            packet
        }
        IpPair::V6(client, server) => {
            let (src, dst) = match direction {
                Direction::Client => (client, server),
                Direction::Server => (server, client),
            };
            let mut pseudo = Vec::with_capacity(40 + tcp.len());
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
            pseudo.extend_from_slice(&tcp);
            tcp[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());

            let mut packet = vec![0u8; 40 + tcp.len()];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
            packet[6] = 6; // TCP
            packet[7] = 64;
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..].copy_from_slice(&tcp);
            packet
        }
    }
}

fn pcap_record(packet: &[u8]) -> Vec<u8> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut record = Vec::with_capacity(16 + packet.len());
    record.extend_from_slice(&(elapsed.as_secs().min(u32::MAX as u64) as u32).to_le_bytes());
    record.extend_from_slice(&elapsed.subsec_micros().to_le_bytes());
    record.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    record.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    record.extend_from_slice(packet);
    record
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, remainder) = bytes.as_chunks::<2>();
    for word in words {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::process::Command;
    use std::time::Instant;
    use tokio::io::AsyncReadExt;

    async fn read_packet(viewer: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut record_header = [0u8; 16];
        viewer.read_exact(&mut record_header).await.unwrap();
        let captured_len = u32::from_le_bytes(record_header[8..12].try_into().unwrap()) as usize;
        let original_len = u32::from_le_bytes(record_header[12..16].try_into().unwrap()) as usize;
        assert_eq!(captured_len, original_len);
        let mut packet = vec![0u8; captured_len];
        viewer.read_exact(&mut packet).await.unwrap();
        packet
    }

    #[test]
    fn pcap_headers_and_ipv4_checksums() {
        assert_eq!(&PCAP_HEADER[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes(PCAP_HEADER[20..24].try_into().unwrap()),
            101
        );
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let packet = ip_tcp_packet(
            IpPair::V4(src, dst),
            Direction::Client,
            41000,
            80,
            123,
            456,
            PSH | ACK,
            7,
            b"GET / HTTP/1.1\r\n",
        );
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(
            u16::from_be_bytes(packet[2..4].try_into().unwrap()) as usize,
            packet.len()
        );
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(u16::from_be_bytes(packet[22..24].try_into().unwrap()), 80);

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
        pseudo.extend_from_slice(&packet[20..]);
        assert_eq!(checksum(&pseudo), 0);

        let record = pcap_record(&packet);
        assert_eq!(
            u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize,
            packet.len()
        );
        assert_eq!(&record[16..], packet);
    }

    #[test]
    fn ipv6_tcp_checksum_and_direction() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = ip_tcp_packet(
            IpPair::V6(src, dst),
            Direction::Server,
            80,
            41000,
            9,
            12,
            PSH | ACK,
            0,
            b"odd",
        );
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(
            u16::from_be_bytes(packet[4..6].try_into().unwrap()) as usize,
            packet.len() - 40
        );
        assert_eq!(&packet[8..24], &dst.octets());
        assert_eq!(&packet[24..40], &src.octets());

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
        pseudo.extend_from_slice(&packet[40..]);
        assert_eq!(checksum(&pseudo), 0);
    }

    #[test]
    fn bounded_capture_queues_report_lost_records() {
        let (viewer_sender, mut viewer_receiver) = tokio_mpsc::channel(1);
        let (file_sender, file_receiver) = std_mpsc::sync_channel(1);
        let output = CaptureOutput {
            viewers: Mutex::new(vec![viewer_sender]),
            file: Some(file_sender),
            slow_viewers: AtomicU64::new(0),
            file_queue_drops: AtomicU64::new(0),
            file_disconnect_drops: AtomicU64::new(0),
        };

        output.broadcast(b"first");
        output.broadcast(b"second");
        output.broadcast(b"third");
        assert_eq!(lock(&output.viewers).len(), 0);
        assert_eq!(output.slow_viewers.load(Ordering::Relaxed), 1);
        assert_eq!(output.file_queue_drops.load(Ordering::Relaxed), 2);
        assert_eq!(viewer_receiver.try_recv().unwrap().len(), 16 + 5);
        assert!(viewer_receiver.try_recv().is_err());
        assert_eq!(file_receiver.try_recv().unwrap().len(), 16 + 5);
        assert!(file_receiver.try_recv().is_err());

        drop(file_receiver);
        output.broadcast(b"fourth");
        assert_eq!(output.file_disconnect_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn viewers_receive_ordered_bidirectional_stream() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let hub = start_capture(Some("127.0.0.1:0".parse().unwrap()), Some(80), None)
                .await
                .unwrap();
            let mut first = tokio::net::TcpStream::connect(hub.local_addr().unwrap())
                .await
                .unwrap();
            let mut second = tokio::net::TcpStream::connect(hub.local_addr().unwrap())
                .await
                .unwrap();
            for viewer in [&mut first, &mut second] {
                let mut header = [0u8; 24];
                viewer.read_exact(&mut header).await.unwrap();
                assert_eq!(header, PCAP_HEADER);
            }

            let flow = hub.flow(
                "192.0.2.10:41234".parse().unwrap(),
                "198.51.100.20:9443".parse().unwrap(),
            );
            flow.client_to_server(b"hello");
            flow.server_to_client(b"world");
            flow.close();
            flow.close();

            let mut first_packets = Vec::new();
            let mut second_packets = Vec::new();
            for _ in 0..11 {
                first_packets.push(read_packet(&mut first).await);
                second_packets.push(read_packet(&mut second).await);
            }
            assert_eq!(first_packets, second_packets);
            let flags: Vec<u8> = first_packets.iter().map(|packet| packet[33]).collect();
            assert_eq!(
                flags,
                [
                    SYN,
                    SYN | ACK,
                    ACK,
                    PSH | ACK,
                    ACK,
                    PSH | ACK,
                    ACK,
                    FIN | ACK,
                    ACK,
                    FIN | ACK,
                    ACK
                ]
            );
            assert_eq!(&first_packets[3][40..], b"hello");
            assert_eq!(&first_packets[5][40..], b"world");

            for (index, packet) in first_packets.iter().enumerate() {
                let from_client = matches!(index, 0 | 2 | 3 | 6 | 7 | 10);
                let (source, destination, source_port, destination_port) = if from_client {
                    ([192, 0, 2, 10], [198, 51, 100, 20], 41234, 80)
                } else {
                    ([198, 51, 100, 20], [192, 0, 2, 10], 80, 41234)
                };
                assert_eq!(&packet[12..16], &source);
                assert_eq!(&packet[16..20], &destination);
                assert_eq!(
                    u16::from_be_bytes(packet[20..22].try_into().unwrap()),
                    source_port
                );
                assert_eq!(
                    u16::from_be_bytes(packet[22..24].try_into().unwrap()),
                    destination_port
                );
                assert_eq!(checksum(&packet[..20]), 0);

                let mut pseudo = Vec::new();
                pseudo.extend_from_slice(&source);
                pseudo.extend_from_slice(&destination);
                pseudo.extend_from_slice(&[0, 6]);
                pseudo.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
                pseudo.extend_from_slice(&packet[20..]);
                assert_eq!(checksum(&pseudo), 0);
            }

            let seq = |packet: &[u8]| u32::from_be_bytes(packet[24..28].try_into().unwrap());
            let ack = |packet: &[u8]| u32::from_be_bytes(packet[28..32].try_into().unwrap());
            assert_eq!(
                seq(&first_packets[3]),
                seq(&first_packets[0]).wrapping_add(1)
            );
            assert_eq!(
                ack(&first_packets[4]),
                seq(&first_packets[3]).wrapping_add(5)
            );
            assert_eq!(
                seq(&first_packets[5]),
                seq(&first_packets[1]).wrapping_add(1)
            );
            assert_eq!(
                ack(&first_packets[6]),
                seq(&first_packets[5]).wrapping_add(5)
            );
        });
    }

    #[test]
    fn output_file_has_header_and_mapped_ports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.pcap");
        fs::write(&path, b"previous capture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let hub = start_capture(None, Some(80), Some(path.clone()))
                .await
                .unwrap();
            assert_eq!(hub.local_addr(), None);
            let flow = hub.flow(
                "192.0.2.10:41234".parse().unwrap(),
                "198.51.100.20:9443".parse().unwrap(),
            );
            flow.client_to_server(b"request");
            flow.server_to_client(b"response");
            flow.close();
            drop(flow);
            drop(hub);
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let bytes = loop {
            let bytes = fs::read(&path).unwrap();
            if bytes.len()
                >= PCAP_HEADER.len() + 11 * (16 + 40) + b"request".len() + b"response".len()
            {
                break bytes;
            }
            assert!(Instant::now() < deadline, "capture output was not flushed");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(&bytes[..24], &PCAP_HEADER);
        let mut offset = 24;
        let mut packets = Vec::new();
        while offset < bytes.len() {
            let size =
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            offset += 16;
            packets.push(&bytes[offset..offset + size]);
            offset += size;
        }
        assert_eq!(packets.len(), 11);
        assert_eq!(
            u16::from_be_bytes(packets[0][20..22].try_into().unwrap()),
            41234
        );
        assert_eq!(
            u16::from_be_bytes(packets[0][22..24].try_into().unwrap()),
            80
        );
        assert_eq!(
            u16::from_be_bytes(packets[1][20..22].try_into().unwrap()),
            80
        );
        assert_eq!(
            u16::from_be_bytes(packets[1][22..24].try_into().unwrap()),
            41234
        );
    }

    #[test]
    fn fifo_waits_for_reader_and_sends_header_on_reconnect() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.fifo");
        assert!(Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let hub = runtime
            .block_on(async { start_capture(None, None, Some(path.clone())).await.unwrap() });

        // A missing reader must never hold up packet generation.
        let start = Instant::now();
        for _ in 0..300 {
            let flow = hub.flow(
                "192.0.2.10:41234".parse().unwrap(),
                "198.51.100.20:9443".parse().unwrap(),
            );
            flow.client_to_server(b"hello");
        }
        assert!(start.elapsed() < Duration::from_secs(2));

        for _ in 0..2 {
            let reader_path = path.clone();
            let (sender, receiver) = std_mpsc::channel();
            let reader = thread::spawn(move || {
                let mut fifo = File::open(reader_path).unwrap();
                let mut header = [0; 24];
                fifo.read_exact(&mut header).unwrap();
                sender.send(header).unwrap();
            });
            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
                PCAP_HEADER
            );
            reader.join().unwrap();
            // Poll the idle writer before the next reader arrives; this must
            // reset its stream even when no packet follows the close.
            thread::sleep(Duration::from_millis(200));
        }
        drop(hub);
    }
}
