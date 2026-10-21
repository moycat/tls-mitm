use anyhow::{anyhow, bail, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

const LEAF_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const RENEW_BEFORE_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

pub struct LeafCredentials {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

struct CachedLeaf {
    credentials: Arc<LeafCredentials>,
    renew_at: SystemTime,
    expires_at: SystemTime,
}

#[derive(Default)]
struct LeafCache {
    entries: HashMap<String, CachedLeaf>,
    next_prune: Option<SystemTime>,
}

impl LeafCache {
    fn prune_expired(&mut self, now: SystemTime) {
        if self.next_prune.is_none_or(|next| now >= next) {
            self.entries.retain(|_, entry| now < entry.expires_at);
            self.next_prune = Some(now + CACHE_PRUNE_INTERVAL);
        }
    }
}

#[derive(Clone)]
pub struct CertificateAuthority {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_chain: Vec<CertificateDer<'static>>,
    cache: Arc<Mutex<LeafCache>>,
}

impl CertificateAuthority {
    pub fn new(cert: &Path, key: &Path) -> Result<Self> {
        let cert_path = fs::canonicalize(cert).context("read CA certificate path")?;
        let key_path = fs::canonicalize(key).context("read CA private-key path")?;
        let cert_chain = CertificateDer::pem_file_iter(&cert_path)
            .context("open CA certificate bundle")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse CA certificate bundle")?;
        if cert_chain.is_empty() {
            bail!("CA certificate bundle contains no certificates");
        }
        let _ = PrivateKeyDer::from_pem_file(&key_path).context("parse CA private key")?;
        let date_check = Command::new("openssl")
            .arg("x509")
            .arg("-in")
            .arg(&cert_path)
            .args(["-checkend", "0", "-noout"])
            .output()
            .context("OpenSSL is required to sign leaf certificates")?;
        if !date_check.status.success() {
            bail!("CA certificate has expired or OpenSSL could not read it");
        }
        let cert_public = Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&cert_path)
            .args(["-pubkey", "-noout"])
            .output()
            .context("read CA certificate public key")?;
        let key_public = Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&key_path)
            .arg("-pubout")
            .output()
            .context("read CA private-key public component")?;
        if !cert_public.status.success() || !key_public.status.success() {
            bail!("could not validate CA certificate and private key");
        }
        if cert_public.stdout != key_public.stdout {
            bail!("CA certificate and private key do not match");
        }
        Ok(Self {
            cert_path,
            key_path,
            cert_chain,
            cache: Arc::new(Mutex::new(LeafCache::default())),
        })
    }

    pub async fn for_host(&self, host: &str) -> Result<Arc<LeafCredentials>> {
        let host = normalize_dns_name(host)?;
        let mut cache = self.cache.lock().await;
        let now = SystemTime::now();
        cache.prune_expired(now);
        if let Some(found) = cache.entries.get(&host) {
            if now < found.renew_at {
                return Ok(found.credentials.clone());
            }
        }
        let previous = cache
            .entries
            .get(&host)
            .filter(|entry| now < entry.expires_at)
            .map(|entry| entry.credentials.clone());

        // OpenSSL signs a leaf for seven days. Start the clock before it runs so
        // these deadlines are conservative even if signing takes some time.
        let signing_started = SystemTime::now();
        let ca = self.clone();
        let name = host.clone();
        let issued = tokio::task::spawn_blocking(move || ca.issue_leaf(&name))
            .await
            .context("certificate signing task failed")
            .and_then(|result| result);
        let leaf = match issued {
            Ok(leaf) => leaf,
            Err(error) => {
                // Keep serving a still-valid leaf if an early renewal fails.
                // The next request will retry; failures are never cached.
                if let Some(previous) = previous {
                    return Ok(previous);
                }
                return Err(error);
            }
        };
        let leaf = Arc::new(leaf);
        let expires_at = signing_started + LEAF_VALIDITY;
        cache.entries.insert(
            host,
            CachedLeaf {
                credentials: leaf.clone(),
                renew_at: expires_at - RENEW_BEFORE_EXPIRY,
                expires_at,
            },
        );
        Ok(leaf)
    }

    fn issue_leaf(&self, host: &str) -> Result<LeafCredentials> {
        let tmp = tempfile::tempdir().context("create temporary certificate directory")?;
        let key = tmp.path().join("leaf.key.pem");
        let csr = tmp.path().join("leaf.csr.pem");
        let cert = tmp.path().join("leaf.crt.pem");
        let ext = tmp.path().join("leaf.ext");

        fs::write(
            &ext,
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{host}\n"
            ),
        )?;

        let common_name = if host.len() <= 64 { host } else { "mitm.local" };
        run_openssl(
            Command::new("openssl")
                .args([
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                ])
                .arg(&key),
            "generate leaf key",
        )?;
        run_openssl(
            Command::new("openssl")
                .args(["req", "-new", "-key"])
                .arg(&key)
                .arg("-out")
                .arg(&csr)
                .arg("-subj")
                .arg(format!("/CN={common_name}")),
            "create leaf CSR",
        )?;

        let mut serial = [0u8; 16];
        SystemRandom::new()
            .fill(&mut serial)
            .map_err(|_| anyhow!("generate certificate serial"))?;
        serial[0] &= 0x7f;
        let serial_hex: String = serial.iter().map(|v| format!("{v:02x}")).collect();
        run_openssl(
            Command::new("openssl")
                .args(["x509", "-req", "-in"])
                .arg(&csr)
                .arg("-CA")
                .arg(&self.cert_path)
                .arg("-CAkey")
                .arg(&self.key_path)
                .args([
                    "-set_serial",
                    &format!("0x{serial_hex}"),
                    "-days",
                    "7",
                    "-sha256",
                    "-extfile",
                ])
                .arg(&ext)
                .arg("-out")
                .arg(&cert),
            "sign leaf certificate",
        )?;
        let mut certs = vec![CertificateDer::from_pem_file(&cert).context("parse signed leaf")?];
        certs.extend(self.cert_chain.iter().cloned());
        let key = PrivateKeyDer::from_pem_file(&key).context("parse generated leaf key")?;
        Ok(LeafCredentials { certs, key })
    }
}

fn run_openssl(cmd: &mut Command, step: &str) -> Result<()> {
    let output = cmd.output().with_context(|| format!("OpenSSL: {step}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("OpenSSL could not {step}: {}", stderr.trim());
    }
    Ok(())
}

pub fn normalize_dns_name(name: &str) -> Result<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        bail!("invalid DNS name");
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            bail!("invalid DNS name");
        }
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::RootCertStore;

    #[test]
    fn validates_dns_names_before_open_ssl() {
        assert_eq!(normalize_dns_name("Example.COM.").unwrap(), "example.com");
        for invalid in ["", ".example", "a..b", "-bad.com", "a/b", "a\nB", "*.x"] {
            assert!(normalize_dns_name(invalid).is_err(), "{invalid}");
        }
    }

    fn test_ca() -> Result<CertificateAuthority> {
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs");
        CertificateAuthority::new(&certs.join("test.crt.pem"), &certs.join("test.key.pem"))
    }

    #[test]
    fn reuses_leaf_for_same_host_and_renews_only_near_expiry() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let ca = test_ca()?;
            let first = ca.for_host("Cache.Example.").await?;
            let same = ca.for_host("cache.example").await?;
            assert!(Arc::ptr_eq(&first, &same));

            let other = ca.for_host("other.example").await?;
            assert!(!Arc::ptr_eq(&first, &other));
            assert!(Arc::ptr_eq(&first, &ca.for_host("cache.example").await?));

            let now = SystemTime::now();
            {
                let mut cache = ca.cache.lock().await;
                let entry = cache.entries.get_mut("cache.example").unwrap();
                assert_eq!(
                    entry.expires_at.duration_since(entry.renew_at)?,
                    RENEW_BEFORE_EXPIRY
                );
                // Simulate a leaf with less than 24 hours remaining.
                entry.renew_at = now - Duration::from_secs(1);
                entry.expires_at = now + RENEW_BEFORE_EXPIRY - Duration::from_secs(1);
            }

            let renewed = ca.for_host("cache.example").await?;
            assert!(!Arc::ptr_eq(&first, &renewed));
            assert_ne!(first.certs[0], renewed.certs[0]);
            assert!(Arc::ptr_eq(&renewed, &ca.for_host("cache.example").await?));
            assert!(Arc::ptr_eq(&other, &ca.for_host("other.example").await?));
            Ok(())
        })
    }

    #[test]
    fn concurrent_requests_share_one_signed_leaf() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let ca = test_ca()?;
            let leaves = join_all((0..8).map(|_| ca.for_host("parallel.example")))
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            for leaf in &leaves[1..] {
                assert!(Arc::ptr_eq(&leaves[0], leaf));
            }
            Ok(())
        })
    }

    #[test]
    fn prunes_expired_leaves_without_discarding_other_cached_hosts() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let ca = test_ca()?;
            let old = ca.for_host("old.example").await?;
            let keep = ca.for_host("keep.example").await?;
            {
                let mut cache = ca.cache.lock().await;
                cache.entries.get_mut("old.example").unwrap().expires_at = SystemTime::UNIX_EPOCH;
                cache.next_prune = Some(SystemTime::UNIX_EPOCH);
                // A large number of valid entries must never clear the whole cache.
                let now = SystemTime::now();
                for index in 0..1025 {
                    cache.entries.insert(
                        format!("placeholder-{index}.example"),
                        CachedLeaf {
                            credentials: keep.clone(),
                            renew_at: now + LEAF_VALIDITY - RENEW_BEFORE_EXPIRY,
                            expires_at: now + LEAF_VALIDITY,
                        },
                    );
                }
            }

            assert!(Arc::ptr_eq(&keep, &ca.for_host("keep.example").await?));
            let cache = ca.cache.lock().await;
            assert!(!cache.entries.contains_key("old.example"));
            assert!(cache.entries.len() > 1024);
            drop(cache);
            assert!(!Arc::ptr_eq(&old, &ca.for_host("old.example").await?));
            Ok(())
        })
    }

    #[test]
    fn intermediate_ca_issues_leaf_and_supplies_full_pem_chain() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let root_key = tmp.path().join("root.key.pem");
        let root_csr = tmp.path().join("root.csr.pem");
        let root_cert = tmp.path().join("root.crt.pem");
        let root_ext = tmp.path().join("root.ext");
        let issuer_key = tmp.path().join("issuer.key.pem");
        let issuer_csr = tmp.path().join("issuer.csr.pem");
        let issuer_cert = tmp.path().join("issuer.crt.pem");
        let issuer_ext = tmp.path().join("issuer.ext");
        let bundle = tmp.path().join("bundle.crt.pem");

        fs::write(
            &root_ext,
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
        )?;
        fs::write(
            &issuer_ext,
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
        )?;
        for key in [&root_key, &issuer_key] {
            run_openssl(
                Command::new("openssl")
                    .args([
                        "ecparam",
                        "-name",
                        "prime256v1",
                        "-genkey",
                        "-noout",
                        "-out",
                    ])
                    .arg(key),
                "generate test CA key",
            )?;
        }
        run_openssl(
            Command::new("openssl")
                .args(["req", "-new", "-key"])
                .arg(&root_key)
                .arg("-out")
                .arg(&root_csr)
                .args(["-subj", "/CN=Local Test Root"]),
            "create test root CSR",
        )?;
        run_openssl(
            Command::new("openssl")
                .args(["x509", "-req", "-in"])
                .arg(&root_csr)
                .arg("-signkey")
                .arg(&root_key)
                .args(["-set_serial", "1", "-days", "7", "-sha256", "-extfile"])
                .arg(&root_ext)
                .arg("-out")
                .arg(&root_cert),
            "sign test root certificate",
        )?;
        run_openssl(
            Command::new("openssl")
                .args(["req", "-new", "-key"])
                .arg(&issuer_key)
                .arg("-out")
                .arg(&issuer_csr)
                .args(["-subj", "/CN=Local Test Intermediate"]),
            "create test intermediate CSR",
        )?;
        run_openssl(
            Command::new("openssl")
                .args(["x509", "-req", "-in"])
                .arg(&issuer_csr)
                .arg("-CA")
                .arg(&root_cert)
                .arg("-CAkey")
                .arg(&root_key)
                .args(["-set_serial", "2", "-days", "7", "-sha256", "-extfile"])
                .arg(&issuer_ext)
                .arg("-out")
                .arg(&issuer_cert),
            "sign test intermediate certificate",
        )?;

        // A missing root does not prevent an intermediate CA from signing a leaf.
        let partial = CertificateAuthority::new(&issuer_cert, &issuer_key)?;
        let partial_leaf = partial.issue_leaf("device.example")?;
        assert_eq!(partial_leaf.certs.len(), 2);

        let mut bundle_pem = fs::read(&issuer_cert)?;
        bundle_pem.extend_from_slice(&fs::read(&root_cert)?);
        fs::write(&bundle, bundle_pem)?;
        assert!(CertificateAuthority::new(&bundle, &root_key).is_err());

        let ca = CertificateAuthority::new(&bundle, &issuer_key)?;
        let leaf = ca.issue_leaf("device.example")?;
        let issuer_der = CertificateDer::from_pem_file(&issuer_cert)?;
        let root_der = CertificateDer::from_pem_file(&root_cert)?;
        assert_eq!(leaf.certs.len(), 3);
        assert_eq!(leaf.certs[1], issuer_der);
        assert_eq!(leaf.certs[2], root_der);

        // A client that trusts the root must be able to validate the returned chain.
        let mut roots = RootCertStore::empty();
        roots.add(root_der)?;
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()?
            .verify_server_cert(
                &leaf.certs[0],
                &leaf.certs[1..],
                &ServerName::try_from("device.example")?,
                &[],
                UnixTime::now(),
            )?;
        Ok(())
    }
}
