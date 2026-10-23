pub use crate::domain::normalize_dns_name;
use anyhow::{anyhow, bail, Context, Result};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use x509_parser::parse_x509_certificate;

const DAY_SECONDS: u64 = 24 * 60 * 60;
const LEAF_VALIDITY: Duration = Duration::from_secs(160 * 60 * 60);
const RENEW_BEFORE_EXPIRY: Duration = Duration::from_secs(DAY_SECONDS);
const CACHE_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

pub struct LeafCredentials {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

struct IssuedLeaf {
    credentials: LeafCredentials,
    expires_at: SystemTime,
}

#[derive(Clone, Copy)]
struct LeafValidity {
    not_before: SystemTime,
    not_after: SystemTime,
}

impl LeafValidity {
    fn random(now: SystemTime) -> Result<Self> {
        let now = now
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        let mut random = [0u8; 8];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| anyhow!("generate certificate validity offset"))?;
        let not_before = UNIX_EPOCH
            + Duration::from_secs(
                now.checked_sub(backdate_seconds(u64::from_le_bytes(random)))
                    .context("system clock is too close to the Unix epoch")?,
            );
        let not_after = not_before
            .checked_add(LEAF_VALIDITY)
            .context("certificate validity exceeds the system time range")?;
        Ok(Self {
            not_before,
            not_after,
        })
    }
}

fn backdate_seconds(random: u64) -> u64 {
    DAY_SECONDS + random % (DAY_SECONDS + 1)
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
    issuer: Arc<Issuer<'static, KeyPair>>,
    cert_chain: Vec<CertificateDer<'static>>,
    cache: Arc<Mutex<LeafCache>>,
}

impl CertificateAuthority {
    pub fn new(cert: &Path, key: &Path) -> Result<Self> {
        let cert_path = fs::canonicalize(cert).context("read CA certificate path")?;
        let key_path = fs::canonicalize(key).context("read CA private-key path")?;
        let cert_chain = load_certificate_chain(&cert_path)?;
        let private_key = load_private_key(&key_path)?;
        let key_pair = KeyPair::try_from(&private_key).context(
            "load CA private key for signing; supported algorithms are RSA, ECDSA, and Ed25519",
        )?;
        {
            let (remainder, parsed) = parse_x509_certificate(cert_chain[0].as_ref())
                .map_err(|error| anyhow!("parse CA certificate: {error}"))?;
            if !remainder.is_empty() {
                bail!("CA certificate contains trailing data");
            }
            if !parsed.validity().is_valid() {
                bail!("CA certificate is not currently valid");
            }
            if !parsed.is_ca() {
                bail!("CA certificate is not authorized to sign certificates");
            }
            if parsed
                .key_usage()
                .map_err(|error| anyhow!("read CA key usage: {error}"))?
                .is_some_and(|usage| !usage.value.key_cert_sign())
            {
                bail!("CA certificate key usage does not permit certificate signing");
            }
            if parsed.public_key().raw != key_pair.subject_public_key_info().as_slice() {
                bail!("CA certificate and private key do not match");
            }
        }
        let issuer: Issuer<'static, KeyPair> = Issuer::from_ca_cert_der(&cert_chain[0], key_pair)
            .context("load CA certificate for signing")?;
        Ok(Self {
            issuer: Arc::new(issuer),
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
                debug!(%host, "reusing cached leaf certificate");
                return Ok(found.credentials.clone());
            }
        }
        let previous = cache
            .entries
            .get(&host)
            .filter(|entry| now < entry.expires_at)
            .map(|entry| entry.credentials.clone());

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
                    warn!(
                        %host,
                        error = %format_args!("{error:#}"),
                        "leaf certificate renewal failed; using cached certificate"
                    );
                    return Ok(previous);
                }
                return Err(error);
            }
        };
        debug!(%host, "issued leaf certificate");
        let expires_at = leaf.expires_at;
        let leaf = Arc::new(leaf.credentials);
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

    fn issue_leaf(&self, host: &str) -> Result<IssuedLeaf> {
        let validity = LeafValidity::random(SystemTime::now())?;
        let common_name = if host.len() <= 64 { host } else { "mitm.local" };
        let mut serial = [0u8; 16];
        SystemRandom::new()
            .fill(&mut serial)
            .map_err(|_| anyhow!("generate certificate serial"))?;
        serial[0] &= 0x7f;
        if serial.iter().all(|byte| *byte == 0) {
            serial[15] = 1;
        }

        let mut params = CertificateParams::new(vec![host.to_owned()])
            .context("create leaf certificate parameters")?;
        params.not_before = validity.not_before.into();
        params.not_after = validity.not_after.into();
        params.serial_number = Some(serial.to_vec().into());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        params.distinguished_name = distinguished_name;

        let key = KeyPair::generate().context("generate leaf key")?;
        let certificate = params
            .signed_by(&key, self.issuer.as_ref())
            .context("sign leaf certificate")?;
        let mut certs = vec![certificate.der().clone()];
        certs.extend(self.cert_chain.iter().cloned());
        let key: PrivateKeyDer<'static> = key.into();
        Ok(IssuedLeaf {
            credentials: LeafCredentials { certs, key },
            expires_at: validity.not_after,
        })
    }
}

fn load_certificate_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let encoded = fs::read(path).context("read CA certificate")?;
    if !looks_like_pem(&encoded) {
        return Ok(vec![CertificateDer::from(encoded)]);
    }
    let certs = CertificateDer::pem_slice_iter(&encoded)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse CA certificate PEM bundle")?;
    if certs.is_empty() {
        bail!("CA certificate PEM contains no CERTIFICATE section");
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let encoded = fs::read(path).context("read CA private key")?;
    if looks_like_pem(&encoded) {
        return PrivateKeyDer::from_pem_slice(&encoded).context(
            "parse CA private key PEM; expected an unencrypted PKCS#8, PKCS#1 RSA, or SEC1 EC key",
        );
    }
    PrivateKeyDer::try_from(encoded).map_err(|error| {
        anyhow!(
            "parse CA private key DER; expected an unencrypted PKCS#8, PKCS#1 RSA, or SEC1 EC key: {error}"
        )
    })
}

fn looks_like_pem(encoded: &[u8]) -> bool {
    encoded
        .windows(b"-----BEGIN".len())
        .any(|window| window == b"-----BEGIN")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use rcgen::{BasicConstraints, CertifiedIssuer};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::RootCertStore;

    #[test]
    fn validates_dns_names_before_signing() {
        assert_eq!(normalize_dns_name("Example.COM.").unwrap(), "example.com");
        for invalid in ["", ".example", "a..b", "-bad.com", "a/b", "a\nB", "*.x"] {
            assert!(normalize_dns_name(invalid).is_err(), "{invalid}");
        }
    }

    fn test_ca() -> Result<CertificateAuthority> {
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("example/certs");
        CertificateAuthority::new(&certs.join("test.crt.pem"), &certs.join("test.key.pem"))
    }

    fn ca_params(common_name: &str, constraints: BasicConstraints) -> Result<CertificateParams> {
        let now = SystemTime::now();
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.not_before = (now - Duration::from_secs(DAY_SECONDS)).into();
        params.not_after = (now + Duration::from_secs(365 * DAY_SECONDS)).into();
        params.is_ca = IsCa::Ca(constraints);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        params.distinguished_name = distinguished_name;
        Ok(params)
    }

    fn der_element(input: &[u8]) -> Result<(u8, &[u8], usize)> {
        let tag = *input.first().context("missing DER tag")?;
        let first_length = *input.get(1).context("missing DER length")?;
        let (length, header_length) = if first_length & 0x80 == 0 {
            (usize::from(first_length), 2)
        } else {
            let length_bytes = usize::from(first_length & 0x7f);
            if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
                bail!("unsupported DER length");
            }
            let encoded = input
                .get(2..2 + length_bytes)
                .context("truncated DER length")?;
            let length = encoded
                .iter()
                .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
            (length, 2 + length_bytes)
        };
        let end = header_length
            .checked_add(length)
            .context("DER length overflow")?;
        let content = input
            .get(header_length..end)
            .context("truncated DER element")?;
        Ok((tag, content, end))
    }

    fn encode_der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 128 {
            encoded.push(content.len() as u8);
        } else {
            let length = content.len().to_be_bytes();
            let first = length.iter().position(|byte| *byte != 0).unwrap();
            encoded.push(0x80 | (length.len() - first) as u8);
            encoded.extend_from_slice(&length[first..]);
        }
        encoded.extend_from_slice(content);
        encoded
    }

    fn pkcs8_private_key(pkcs8: &[u8]) -> Result<&[u8]> {
        let (tag, outer, _) = der_element(pkcs8)?;
        if tag != 0x30 {
            bail!("PKCS#8 key is not a sequence");
        }
        let (_, _, version_length) = der_element(outer)?;
        let (_, _, algorithm_length) = der_element(&outer[version_length..])?;
        let (tag, private_key, _) = der_element(&outer[version_length + algorithm_length..])?;
        if tag != 0x04 {
            bail!("PKCS#8 private key is not an octet string");
        }
        Ok(private_key)
    }

    fn compact_ec_pkcs8(pkcs8: &[u8]) -> Result<Vec<u8>> {
        let (tag, outer, _) = der_element(pkcs8)?;
        if tag != 0x30 {
            bail!("PKCS#8 key is not a sequence");
        }
        let (_, _, version_length) = der_element(outer)?;
        let (_, _, algorithm_length) = der_element(&outer[version_length..])?;
        let private_offset = version_length + algorithm_length;
        let (tag, private_key, private_length) = der_element(&outer[private_offset..])?;
        if tag != 0x04 {
            bail!("PKCS#8 private key is not an octet string");
        }
        let (tag, ec_key, _) = der_element(private_key)?;
        if tag != 0x30 {
            bail!("EC private key is not a sequence");
        }

        let mut compact_ec_key = Vec::new();
        let mut remaining = ec_key;
        while !remaining.is_empty() {
            let (tag, _, length) = der_element(remaining)?;
            if tag != 0xa1 {
                compact_ec_key.extend_from_slice(&remaining[..length]);
            }
            remaining = &remaining[length..];
        }

        let private_key = encode_der(0x30, &compact_ec_key);
        let private_key = encode_der(0x04, &private_key);
        let mut compact = outer[..private_offset].to_vec();
        compact.extend_from_slice(&private_key);
        compact.extend_from_slice(&outer[private_offset + private_length..]);
        Ok(encode_der(0x30, &compact))
    }

    fn private_key_pem(label: &str, der: Vec<u8>) -> Vec<u8> {
        pem::encode(&pem::Pem::new(label, der)).into_bytes()
    }

    fn assert_ca_loads(directory: &Path, name: &str, cert: &[u8], key: &[u8]) -> Result<()> {
        let cert_path = directory.join(format!("{name}.crt"));
        let key_path = directory.join(format!("{name}.key"));
        fs::write(&cert_path, cert)?;
        fs::write(&key_path, key)?;
        let ca = CertificateAuthority::new(&cert_path, &key_path)?;
        assert_eq!(ca.issue_leaf("format.example")?.credentials.certs.len(), 2);
        Ok(())
    }

    #[test]
    fn random_backdate_covers_the_inclusive_one_to_two_day_range() {
        assert_eq!(backdate_seconds(0), DAY_SECONDS);
        assert_eq!(backdate_seconds(DAY_SECONDS), 2 * DAY_SECONDS);
        assert_eq!(backdate_seconds(DAY_SECONDS + 1), DAY_SECONDS);
        for random in [1, DAY_SECONDS - 1, u32::MAX as u64, u64::MAX] {
            assert!((DAY_SECONDS..=2 * DAY_SECONDS).contains(&backdate_seconds(random)));
        }
    }

    #[test]
    fn leaf_is_valid_for_160_hours_and_backdated_one_to_two_days() -> Result<()> {
        let ca = test_ca()?;
        let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let leaf = ca.issue_leaf("validity.example")?;
        let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let (_, parsed) = parse_x509_certificate(leaf.credentials.certs[0].as_ref())
            .map_err(|error| anyhow!("parse issued certificate: {error}"))?;
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();

        assert!(not_before >= before - 2 * DAY_SECONDS as i64 - 1);
        assert!(not_before <= after - DAY_SECONDS as i64 + 1);
        assert_eq!(not_after - not_before, LEAF_VALIDITY.as_secs() as i64);
        assert_eq!(
            leaf.expires_at.duration_since(UNIX_EPOCH)?.as_secs() as i64,
            not_after
        );
        Ok(())
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
                let (_, parsed) = parse_x509_certificate(first.certs[0].as_ref())
                    .map_err(|error| anyhow!("parse cached certificate: {error}"))?;
                assert_eq!(
                    entry.expires_at.duration_since(UNIX_EPOCH)?.as_secs() as i64,
                    parsed.validity().not_after.timestamp()
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
        let root_cert = tmp.path().join("root.crt.pem");
        let issuer_key = tmp.path().join("issuer.key.pem");
        let issuer_cert = tmp.path().join("issuer.crt.pem");
        let bundle = tmp.path().join("bundle.crt.pem");

        let root = CertifiedIssuer::self_signed(
            ca_params("Local Test Root", BasicConstraints::Unconstrained)?,
            KeyPair::generate()?,
        )?;
        let issuer = CertifiedIssuer::signed_by(
            ca_params("Local Test Intermediate", BasicConstraints::Constrained(0))?,
            KeyPair::generate()?,
            &root,
        )?;
        fs::write(&root_key, root.key().serialize_pem())?;
        fs::write(&root_cert, root.pem())?;
        fs::write(&issuer_key, issuer.key().serialize_pem())?;
        fs::write(&issuer_cert, issuer.pem())?;

        // A missing root does not prevent an intermediate CA from signing a leaf.
        let partial = CertificateAuthority::new(&issuer_cert, &issuer_key)?;
        let partial_leaf = partial.issue_leaf("device.example")?;
        assert_eq!(partial_leaf.credentials.certs.len(), 2);

        let mut bundle_pem = fs::read(&issuer_cert)?;
        bundle_pem.extend_from_slice(&fs::read(&root_cert)?);
        fs::write(&bundle, bundle_pem)?;
        assert!(CertificateAuthority::new(&bundle, &root_key).is_err());

        let ca = CertificateAuthority::new(&bundle, &issuer_key)?;
        let leaf = ca.issue_leaf("device.example")?;
        let issuer_der = CertificateDer::from_pem_file(&issuer_cert)?;
        let root_der = CertificateDer::from_pem_file(&root_cert)?;
        assert_eq!(leaf.credentials.certs.len(), 3);
        assert_eq!(leaf.credentials.certs[1], issuer_der);
        assert_eq!(leaf.credentials.certs[2], root_der);

        // A client that trusts the root must be able to validate the returned chain.
        let mut roots = RootCertStore::empty();
        roots.add(root_der)?;
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()?
            .verify_server_cert(
                &leaf.credentials.certs[0],
                &leaf.credentials.certs[1..],
                &ServerName::try_from("device.example")?,
                &[],
                UnixTime::now(),
            )?;
        Ok(())
    }

    #[test]
    fn loads_common_ca_certificate_and_private_key_formats() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let ec = CertifiedIssuer::self_signed(
            ca_params("P-384 Test CA", BasicConstraints::Unconstrained)?,
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
        )?;
        let ec_pkcs8 = ec.key().serialize_der();
        let ec_sec1 = pkcs8_private_key(&ec_pkcs8)?.to_vec();
        let ec_cert_pem = ec.pem().into_bytes();
        assert_ca_loads(
            tmp.path(),
            "compact-pkcs8-pem",
            &ec_cert_pem,
            &private_key_pem("PRIVATE KEY", compact_ec_pkcs8(&ec_pkcs8)?),
        )?;
        assert_ca_loads(
            tmp.path(),
            "sec1-pem",
            &ec_cert_pem,
            &private_key_pem("EC PRIVATE KEY", ec_sec1.clone()),
        )?;
        assert_ca_loads(tmp.path(), "pkcs8-der", ec.der().as_ref(), &ec_pkcs8)?;
        assert_ca_loads(tmp.path(), "sec1-der", &ec_cert_pem, &ec_sec1)?;

        let rsa = CertifiedIssuer::self_signed(
            ca_params("RSA Test CA", BasicConstraints::Unconstrained)?,
            KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?,
        )?;
        let rsa_pkcs1 = pkcs8_private_key(&rsa.key().serialize_der())?.to_vec();
        let rsa_cert_pem = rsa.pem().into_bytes();
        assert_ca_loads(
            tmp.path(),
            "pkcs1-pem",
            &rsa_cert_pem,
            &private_key_pem("RSA PRIVATE KEY", rsa_pkcs1.clone()),
        )?;
        assert_ca_loads(tmp.path(), "pkcs1-der", rsa.der().as_ref(), &rsa_pkcs1)?;

        let ed25519 = CertifiedIssuer::self_signed(
            ca_params("Ed25519 Test CA", BasicConstraints::Unconstrained)?,
            KeyPair::generate_for(&rcgen::PKCS_ED25519)?,
        )?;
        let ed25519_pkcs8 = ed25519.key().serialize_der();
        let ed25519_cert_pem = ed25519.pem().into_bytes();
        assert_ca_loads(
            tmp.path(),
            "ed25519-pem",
            &ed25519_cert_pem,
            &private_key_pem("PRIVATE KEY", ed25519_pkcs8.clone()),
        )?;
        assert_ca_loads(
            tmp.path(),
            "ed25519-der",
            ed25519.der().as_ref(),
            &ed25519_pkcs8,
        )?;

        let unsupported_cert = tmp.path().join("unsupported-cert.pem");
        fs::write(
            &unsupported_cert,
            pem::encode(&pem::Pem::new(
                "TRUSTED CERTIFICATE",
                ec.der().as_ref().to_vec(),
            )),
        )?;
        let error = load_certificate_chain(&unsupported_cert)
            .err()
            .context("expected unsupported certificate PEM label to be rejected")?;
        assert!(
            format!("{error:#}").contains("contains no CERTIFICATE section"),
            "{error:#}"
        );

        let encrypted_key = tmp.path().join("encrypted-key.pem");
        fs::write(
            &encrypted_key,
            pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", vec![0x30, 0x00])),
        )?;
        let error = load_private_key(&encrypted_key)
            .err()
            .context("expected encrypted private key to be rejected")?;
        assert!(
            format!("{error:#}")
                .contains("expected an unencrypted PKCS#8, PKCS#1 RSA, or SEC1 EC key"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn rejects_expired_ca_without_external_tools() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let cert = tmp.path().join("expired.crt.pem");
        let key = tmp.path().join("expired.key.pem");
        let now = SystemTime::now();
        let signing_key = KeyPair::generate()?;
        let mut params = ca_params("Expired Test CA", BasicConstraints::Unconstrained)?;
        params.not_before = (now - Duration::from_secs(2 * DAY_SECONDS)).into();
        params.not_after = (now - Duration::from_secs(DAY_SECONDS)).into();
        let expired = CertifiedIssuer::self_signed(params, signing_key)?;
        fs::write(&cert, expired.pem())?;
        fs::write(&key, expired.key().serialize_pem())?;

        let error = CertificateAuthority::new(&cert, &key)
            .err()
            .context("expected expired CA to be rejected")?;
        assert!(
            format!("{error:#}").contains("CA certificate is not currently valid"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn rejects_certificates_that_cannot_sign() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let now = SystemTime::now();

        for (name, is_ca, key_usages, expected) in [
            (
                "leaf",
                IsCa::ExplicitNoCa,
                vec![KeyUsagePurpose::DigitalSignature],
                "is not authorized to sign certificates",
            ),
            (
                "wrong-usage",
                IsCa::Ca(BasicConstraints::Unconstrained),
                vec![KeyUsagePurpose::DigitalSignature],
                "key usage does not permit certificate signing",
            ),
        ] {
            let cert_path = tmp.path().join(format!("{name}.crt.pem"));
            let key_path = tmp.path().join(format!("{name}.key.pem"));
            let signing_key = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.not_before = (now - Duration::from_secs(DAY_SECONDS)).into();
            params.not_after = (now + Duration::from_secs(DAY_SECONDS)).into();
            params.is_ca = is_ca;
            params.key_usages = key_usages;
            let certificate = params.self_signed(&signing_key)?;
            fs::write(&cert_path, certificate.pem())?;
            fs::write(&key_path, signing_key.serialize_pem())?;

            let error = CertificateAuthority::new(&cert_path, &key_path)
                .err()
                .with_context(|| format!("expected {name} certificate to be rejected"))?;
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        Ok(())
    }
}
