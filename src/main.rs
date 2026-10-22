use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::path::PathBuf;
use tls_mitm::capture::start_capture;
use tls_mitm::cert::CertificateAuthority;
use tls_mitm::config::{load, RuntimeConfig};
use tls_mitm::dns::serve_dns;
use tls_mitm::proxy::{build_upstream_client, Proxy, ProxyConfig};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

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
    let settings = load(&args.config)?;
    debug!(
        config = %args.config.display(),
        proxy_listeners = settings.proxy.listen.len(),
        routes = settings.routes.len(),
        dns_enabled = settings.dns.is_some(),
        capture_enabled = settings.capture.is_some(),
        "configuration loaded"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(settings))
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

async fn run(settings: RuntimeConfig) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("could not initialize TLS crypto provider"))?;

    let RuntimeConfig {
        proxy: settings,
        routes,
        dns,
        capture,
    } = settings;
    let ca = CertificateAuthority::new(&settings.ca_cert, &settings.ca_key)?;
    let upstream_client = build_upstream_client(settings.upstream_ca.as_deref())?;

    let capture = match capture {
        Some(capture) => {
            let hub =
                start_capture(capture.listen, capture.map_port, capture.output.clone()).await?;
            if let Some(listen) = hub.local_addr() {
                info!(%listen, "PCAP stream listening");
            }
            if let Some(output) = capture.output {
                info!(path = %output.display(), "PCAP file output enabled");
            }
            Some(hub)
        }
        None => None,
    };

    let mut proxies = Vec::with_capacity(settings.listen.len());
    for listen in settings.listen {
        let upstream_port = settings.upstream_port.unwrap_or(listen.port());
        if upstream_port == 0 {
            bail!("proxy.upstream_port is required when a listener uses port 0");
        }
        let proxy = Proxy::bind(ProxyConfig {
            listen,
            default_upstream_port: upstream_port,
            resolver: settings.resolver,
            ca: ca.clone(),
            routes: routes.clone(),
            default_host: settings.default_host.clone(),
            upstream_client: upstream_client.clone(),
            capture: capture.clone(),
        })
        .await?;
        info!(listen = %proxy.local_addr()?, "TLS proxy listening");
        proxies.push(proxy);
    }
    let proxy_future = async move {
        futures::future::try_join_all(proxies.into_iter().map(Proxy::serve))
            .await
            .map(|_| ())
    };
    if let Some(dns) = dns {
        info!(listen = %dns.bind, upstream = %dns.upstream, "DNS server listening");
        futures::try_join!(proxy_future, serve_dns(dns))?;
    } else {
        proxy_future.await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
