//! Local certificate authority for TLS termination (MITM).
//!
//! To inspect request bodies, honmoon terminates the agent's TLS by minting a
//! per-host leaf certificate signed by a local root CA. The agent must trust
//! this CA (installed out-of-band into its trust store). The CA is generated on
//! first use and persisted so leaf certs stay stable across restarts.
//!
//! The CA private key is a MITM root — anyone holding it can impersonate any
//! host to a trusting agent. It is written with `0600` permissions and is never
//! logged. Only the CA *certificate* ([`CaMaterial::cert_pem`]) is safe to
//! distribute (it is what agents install to trust the proxy).

use std::fs;
use std::io;
use std::path::Path;

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DnType, Error as RcgenError, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;

/// Max number of minted per-host leaf certificates cached in memory.
const LEAF_CACHE_SIZE: u64 = 1_000;

/// PEM-encoded CA material.
///
/// `cert_pem` is the CA certificate (safe to distribute — agents install it to
/// trust the proxy). `key_pem` is the private signing key and is kept secret.
pub struct CaMaterial {
    /// The CA certificate in PEM form (public — distribute to agents).
    pub cert_pem: String,
    /// The CA private key in PEM form (secret — MITM root).
    key_pem: String,
}

impl CaMaterial {
    /// Load the CA from `cert_path`/`key_path`, generating and persisting a new
    /// one if either file is missing.
    ///
    /// The key file is created with `0600` permissions on Unix.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> io::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            return Ok(Self {
                cert_pem: fs::read_to_string(cert_path)?,
                key_pem: fs::read_to_string(key_path)?,
            });
        }

        let material =
            Self::generate().map_err(|e| io::Error::other(format!("generate CA: {e}")))?;
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(cert_path, &material.cert_pem)?;
        write_secret(key_path, &material.key_pem)?;
        Ok(material)
    }

    /// Generate a fresh self-signed root CA in memory (not persisted).
    pub fn generate() -> Result<Self, RcgenError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "Honmoon MITM CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Honmoon");
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// Build the hudsucker [`RcgenAuthority`] that mints per-host leaf certs on
    /// demand and caches them.
    pub fn authority(&self) -> Result<RcgenAuthority, RcgenError> {
        let key = KeyPair::from_pem(&self.key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, key)?;
        Ok(RcgenAuthority::new(
            issuer,
            LEAF_CACHE_SIZE,
            aws_lc_rs::default_provider(),
        ))
    }
}

/// Write a secret file with owner-only permissions (`0600`) on Unix.
#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch directory for a single test.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("honmoon-ca-{}-{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn generate_produces_a_usable_authority() {
        let ca = CaMaterial::generate().expect("generate CA");
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        // The generated material must build a leaf-minting authority.
        ca.authority().expect("build authority");
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = scratch_dir("idempotent");
        let cert = dir.join("ca.cer");
        let key = dir.join("ca.key");

        let first = CaMaterial::load_or_generate(&cert, &key).expect("first load");
        assert!(cert.exists() && key.exists());
        // A second call must reuse the persisted material, not regenerate it.
        let second = CaMaterial::load_or_generate(&cert, &key).expect("second load");
        assert_eq!(first.cert_pem, second.cert_pem);
        assert_eq!(first.key_pem, second.key_pem);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("perms");
        let cert = dir.join("ca.cer");
        let key = dir.join("ca.key");
        CaMaterial::load_or_generate(&cert, &key).expect("generate");

        let mode = fs::metadata(&key)
            .expect("key metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "CA key must be 0600");

        let _ = fs::remove_dir_all(&dir);
    }
}
