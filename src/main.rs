use anyhow::{anyhow, bail, Result};
use clap::Parser;
use std::path::PathBuf;
use tls_mitm::capture::start_capture;
use tls_mitm::cert::CertificateAuthority;
use tls_mitm::config::{load, RuntimeConfig};
use tls_mitm::dns::serve_dns;
use tls_mitm::proxy::{build_upstream_client, Proxy, ProxyConfig};

#[derive(Parser, Debug)]
#[command(version, about = "SNI-based TLS security test proxy")]
struct Args {
    /// TOML configuration file.
    #[arg(long, default_value = "example/config.toml")]
    config: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let settings = load(&args.config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(settings))
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
                eprintln!("PCAP stream listening on {listen}");
            }
            if let Some(output) = capture.output {
                eprintln!("PCAP output path: {}", output.display());
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
        eprintln!("TLS proxy listening on {}", proxy.local_addr()?);
        proxies.push(proxy);
    }
    let proxy_future = async move {
        futures::future::try_join_all(proxies.into_iter().map(Proxy::serve))
            .await
            .map(|_| ())
    };
    if let Some(dns) = dns {
        eprintln!("DNS listening on {}", dns.bind);
        futures::try_join!(proxy_future, serve_dns(dns))?;
    } else {
        proxy_future.await?;
    }
    Ok(())
}
