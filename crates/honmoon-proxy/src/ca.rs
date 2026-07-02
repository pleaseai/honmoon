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
    /// The key file is created with `0600` permissions on Unix; a pre-existing
    /// key with looser permissions is tightened back to `0600` on load. Loaded
    /// material is validated (the pair must build an authority) so corrupt or
    /// partially-written files fail startup with an error instead of panicking
    /// later at [`authority`](Self::authority).
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> io::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            let material = Self {
                cert_pem: fs::read_to_string(cert_path)?,
                key_pem: fs::read_to_string(key_path)?,
            };
            material.authority().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid CA material in {} / {}: {e} (delete both files to regenerate)",
                        cert_path.display(),
                        key_path.display()
                    ),
                )
            })?;
            enforce_secret_permissions(key_path)?;
            return Ok(material);
        }

        let material =
            Self::generate().map_err(|e| io::Error::other(format!("generate CA: {e}")))?;
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Key first: if the process dies between the two writes, the missing
        // cert makes the next start regenerate the pair instead of loading a
        // half-written one.
        write_secret(key_path, &material.key_pem)?;
        fs::write(cert_path, &material.cert_pem)?;
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
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode` only applies to newly-created files; a pre-existing key with
    // looser permissions must be tightened explicitly.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
}

/// Force owner-only permissions (`0600`) on an existing secret file (Unix).
#[cfg(unix)]
fn enforce_secret_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn enforce_secret_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
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

    #[test]
    fn load_rejects_corrupt_material() {
        let dir = scratch_dir("corrupt");
        let cert = dir.join("ca.cer");
        let key = dir.join("ca.key");
        CaMaterial::load_or_generate(&cert, &key).expect("generate");

        // Simulate a partial write (process killed between cert and key): an
        // empty key must fail the load with an error, not panic later.
        fs::write(&key, "").expect("truncate key");
        // (No `expect_err`: CaMaterial deliberately has no Debug — secret key.)
        let Err(err) = CaMaterial::load_or_generate(&cert, &key) else {
            panic!("corrupt key must fail the load");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_permissions_are_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("tighten");
        let cert = dir.join("ca.cer");
        let key = dir.join("ca.key");
        CaMaterial::load_or_generate(&cert, &key).expect("generate");

        // Loosen the key, then reload: the load path must restore 0600.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("loosen");
        CaMaterial::load_or_generate(&cert, &key).expect("reload");
        let mode = fs::metadata(&key)
            .expect("key metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "reload must tighten key to 0600");

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
