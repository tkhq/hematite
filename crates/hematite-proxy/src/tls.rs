//! Part 05 §3 — TLS MITM leaf minting and the per-hostname cert cache.
//!
//! Leaves are minted per SNI target and signed by the operator's CA:
//! ECDSA P-256, random ≥64-bit serial, CN + single SAN = the target,
//! serverAuth EKU, short-lived (`leaf_cert_expiry_hours`, default 72).
//! The cache is an LRU keyed by target; concurrent misses single-flight
//! (threat T8: mint floods).

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::metrics::Metrics;

use lru::LruCache;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String,
    IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::sync::watch;

/// The operator CA that signs minted leaves (Part 05 §3).
pub struct SigningCa {
    key: KeyPair,
    /// The CA as an rcgen issuer (reconstructed from the loaded params).
    ca_cert: Certificate,
    /// DER of the original CA cert, included in every served chain.
    ca_der: CertificateDer<'static>,
    expiry_hours: u64,
    /// Serial counter seeded from the clock; the exact value is not
    /// security-relevant beyond being unpredictable and unique.
    serial_seed: Mutex<u64>,
}

/// Decode the first PEM CERTIFICATE block to DER (reusing the kernel's
/// base64 to keep the dependency budget closed).
fn pem_cert_to_der(pem: &str) -> Result<CertificateDer<'static>, TlsError> {
    let start = pem
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| TlsError("ca_cert PEM has no CERTIFICATE block".into()))?;
    let after = &pem[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = after
        .find("-----END CERTIFICATE-----")
        .ok_or_else(|| TlsError("ca_cert PEM CERTIFICATE block unterminated".into()))?;
    let b64: String = after[..end].split_whitespace().collect();
    let der = hematite_kernel::codec::base64_decode(&b64)
        .ok_or_else(|| TlsError("ca_cert PEM body is not valid base64".into()))?;
    Ok(CertificateDer::from(der))
}

/// Install the ring crypto provider as the process default. Idempotent:
/// a second call is a no-op. Must run before any `ServerConfig::builder()`.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
pub struct TlsError(pub String);

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tls: {}", self.0)
    }
}

impl SigningCa {
    /// Load the CA from PEM cert + PEM key (Part 09: `tls.ca_cert`,
    /// `tls.ca_key`).
    pub fn from_pem(cert_pem: &str, key_pem: &str, expiry_hours: u64) -> Result<Self, TlsError> {
        let key = KeyPair::from_pem(key_pem).map_err(|e| TlsError(format!("ca key: {e}")))?;
        // Reconstruct issuer params (subject DN, key identifiers) from the
        // CA cert so leaves are issued under the CA's identity.
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| TlsError(format!("ca cert: {e}")))?;
        let ca_cert = params
            .self_signed(&key)
            .map_err(|e| TlsError(format!("ca reconstruct: {e}")))?;
        // The served chain uses the operator's original CA cert bytes.
        let ca_der = pem_cert_to_der(cert_pem)?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5eed_5eed);
        Ok(SigningCa {
            key,
            ca_cert,
            ca_der,
            expiry_hours,
            serial_seed: Mutex::new(seed),
        })
    }

    fn next_serial(&self) -> SerialNumber {
        let mut seed = self.serial_seed.lock().expect("serial lock");
        // xorshift for an unpredictable, non-repeating 64-bit serial.
        let mut x = *seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *seed = x;
        SerialNumber::from_slice(&x.to_be_bytes())
    }

    /// Mint a leaf for `target` (a hostname or an IP literal). The served
    /// chain is [leaf, CA].
    pub fn mint(&self, target: &str) -> Result<CertifiedLeaf, TlsError> {
        let mut params = CertificateParams::default();

        let san = match target.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                Ia5String::try_from(target.to_string())
                    .map_err(|_| TlsError(format!("invalid dNSName: {target:?}")))?,
            ),
        };
        params.subject_alt_names = vec![san];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, target);
        params.distinguished_name = dn;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serial_number = Some(self.next_serial());

        let now = SystemTime::now();
        params.not_before = (now - std::time::Duration::from_secs(60)).into();
        params.not_after = (now + std::time::Duration::from_secs(self.expiry_hours * 3600)).into();

        let leaf_key = KeyPair::generate().map_err(|e| TlsError(format!("leaf keygen: {e}")))?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.key)
            .map_err(|e| TlsError(format!("leaf sign: {e}")))?;

        Ok(CertifiedLeaf {
            chain: vec![leaf.der().clone(), self.ca_der.clone()],
            key: PrivateKeyDer::try_from(leaf_key.serialize_der())
                .map_err(|e| TlsError(format!("leaf key der: {e}")))?,
        })
    }
}

/// A minted leaf plus its private key and the CA in the chain.
pub struct CertifiedLeaf {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl CertifiedLeaf {
    /// A rustls `ServerConfig` serving this leaf, ALPN h2 + http/1.1.
    pub fn server_config(self) -> Result<ServerConfig, TlsError> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.chain, self.key)
            .map_err(|e| TlsError(format!("server config: {e}")))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::try_unwrap(Arc::new(config)).unwrap_or_else(|a| (*a).clone()))
    }
}

/// Per-hostname LRU cert cache with single-flight minting (Part 05 §3,
/// threat T8).
pub struct CertCache {
    ca: Arc<SigningCa>,
    cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
    /// In-flight mints, so concurrent misses for one target mint once.
    inflight: Mutex<HashMap<String, watch::Receiver<Option<Arc<ServerConfig>>>>>,
    /// Metrics registry, set after construction via `set_metrics`.
    metrics: Mutex<Option<Arc<Metrics>>>,
}

impl CertCache {
    pub fn new(ca: Arc<SigningCa>, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        CertCache {
            ca,
            cache: Mutex::new(LruCache::new(capacity)),
            inflight: Mutex::new(HashMap::new()),
            metrics: Mutex::new(None),
        }
    }

    /// Attach a metrics registry for hit/miss instrumentation.
    pub fn set_metrics(&self, m: Arc<Metrics>) {
        *self.metrics.lock().expect("metrics lock") = Some(m);
    }

    /// Get or mint the `ServerConfig` for `target`.
    pub async fn get(&self, target: &str) -> Result<Arc<ServerConfig>, TlsError> {
        if let Some(hit) = self.cache.lock().expect("cache lock").get(target).cloned() {
            if let Some(m) = self.metrics.lock().expect("metrics lock").as_ref() {
                m.inc_tls_cache(true);
            }
            return Ok(hit);
        }
        // Single-flight: either become the minter or await the in-flight one.
        enum Role {
            Mint(watch::Sender<Option<Arc<ServerConfig>>>),
            Await(watch::Receiver<Option<Arc<ServerConfig>>>),
        }
        let role = {
            let mut inflight = self.inflight.lock().expect("inflight lock");
            match inflight.get(target) {
                Some(rx) => Role::Await(rx.clone()),
                None => {
                    let (tx, rx) = watch::channel(None);
                    inflight.insert(target.to_string(), rx);
                    Role::Mint(tx)
                }
            }
        };

        match role {
            Role::Await(mut rx) => {
                if let Some(m) = self.metrics.lock().expect("metrics lock").as_ref() {
                    m.inc_tls_cache(false);
                }
                // Wait for the minter to publish.
                while rx.borrow().is_none() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                let value = rx.borrow().clone();
                value.ok_or_else(|| TlsError(format!("mint failed for {target:?}")))
            }
            Role::Mint(tx) => {
                if let Some(m) = self.metrics.lock().expect("metrics lock").as_ref() {
                    m.inc_tls_cache(false);
                }
                let result = self.ca.mint(target).and_then(|leaf| leaf.server_config());
                let published = match result {
                    Ok(config) => {
                        let config = Arc::new(config);
                        self.cache
                            .lock()
                            .expect("cache lock")
                            .put(target.to_string(), config.clone());
                        Some(config)
                    }
                    Err(_) => None,
                };
                self.inflight.lock().expect("inflight lock").remove(target);
                let _ = tx.send(published.clone());
                published.ok_or_else(|| TlsError(format!("mint failed for {target:?}")))
            }
        }
    }
}
