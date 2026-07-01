// SPDX-License-Identifier: GPL-3.0-or-later
//! TLS connection factory with gateway certificate verification.
//!
//! Verification mirrors upstream openfortivpn's two-stage `ssl_verify_cert`:
//! a certificate is accepted if either (1) normal PKI validation *including*
//! hostname matching succeeds, or (2) the leaf certificate's SHA256 digest is in
//! the `--trusted-cert` whitelist. On failure we print the digest plus the exact
//! command needed to trust it — upstream behavior, no interactive prompt.

use crate::cli::Config;
use anyhow::{Context, Result, bail};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::{X509, X509Ref};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

fn parse_tls_version(v: &str) -> Result<SslVersion> {
    Ok(match v.trim() {
        "1.0" | "1" => SslVersion::TLS1,
        "1.1" => SslVersion::TLS1_1,
        "1.2" => SslVersion::TLS1_2,
        "1.3" => SslVersion::TLS1_3,
        other => bail!(
            "invalid --min-tls value: {} (expected 1.0/1.1/1.2/1.3)",
            other
        ),
    })
}

/// Lowercase, separator-free hex of a certificate's SHA256 digest.
pub fn cert_sha256_hex(cert: &X509Ref) -> String {
    let digest = cert
        .digest(MessageDigest::sha256())
        .expect("sha256 of certificate");
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Default)]
struct CertState {
    chain_ok: bool,
    leaf_digest: Option<String>,
}

/// Creates verified TLS streams to a single gateway.
#[derive(Clone)]
pub struct TlsFactory {
    host: String,
    port: u16,
    trusted: Vec<String>,
    ca_file: Option<PathBuf>,
    min_tls: String,
    cipher_list: Option<String>,
    insecure_ssl: bool,
    user_cert: Option<String>,
    user_key: Option<PathBuf>,
    pem_passphrase: Option<String>,
}

impl TlsFactory {
    pub fn from_config(config: &Config) -> Self {
        let trusted = config
            .trusted_cert
            .iter()
            .map(|c| c.replace(':', "").to_lowercase())
            .collect();
        Self {
            host: config.host.clone(),
            port: config.port,
            trusted,
            ca_file: config.ca_file.clone(),
            min_tls: config.min_tls.clone(),
            cipher_list: config.cipher_list.clone(),
            insecure_ssl: config.insecure_ssl,
            user_cert: config.user_cert.clone(),
            user_key: config.user_key.clone(),
            pem_passphrase: config.pem_passphrase.clone(),
        }
    }

    /// Apply protocol version, cipher, and client-certificate options.
    fn configure_builder(&self, builder: &mut openssl::ssl::SslConnectorBuilder) -> Result<()> {
        builder.set_min_proto_version(Some(parse_tls_version(&self.min_tls)?))?;

        if self.insecure_ssl {
            builder.set_security_level(0);
        }
        if let Some(list) = &self.cipher_list {
            builder.set_cipher_list(list)?;
        }

        if let Some(cert) = &self.user_cert {
            let x509 = if cert.starts_with("pkcs11:") {
                self.load_pkcs11_cert(cert)?
            } else {
                let cert_pem = std::fs::read(cert)
                    .with_context(|| format!("reading client certificate {}", cert))?;
                X509::from_pem(&cert_pem).context("parsing client certificate PEM")?
            };
            builder.set_certificate(&x509)?;

            let key_ref = self.user_key.as_deref().map(|p| p.to_string_lossy());
            if let Some(uri) = key_ref.as_deref().filter(|k| k.starts_with("pkcs11:")) {
                self.set_pkcs11_key(builder, uri)?;
            } else {
                let key_path = self
                    .user_key
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new(cert));
                let key_pem = std::fs::read(key_path)
                    .with_context(|| format!("reading client key {:?}", key_path))?;
                let pkey = match &self.pem_passphrase {
                    Some(pass) => PKey::private_key_from_pem_passphrase(&key_pem, pass.as_bytes())
                        .context("decrypting client key with passphrase")?,
                    None => {
                        PKey::private_key_from_pem(&key_pem).context("parsing client key PEM")?
                    }
                };
                builder.set_private_key(&pkey)?;
            }
            builder.check_private_key()?;
        }
        Ok(())
    }

    #[cfg(feature = "pkcs11")]
    fn set_pkcs11_key(
        &self,
        builder: &mut openssl::ssl::SslConnectorBuilder,
        uri: &str,
    ) -> Result<()> {
        let pkey = crate::transport::pkcs11::load_private_key(uri)?;
        builder.set_private_key(&pkey)?;
        Ok(())
    }

    #[cfg(not(feature = "pkcs11"))]
    fn set_pkcs11_key(
        &self,
        _builder: &mut openssl::ssl::SslConnectorBuilder,
        _uri: &str,
    ) -> Result<()> {
        bail!("PKCS#11 keys require building with `--features pkcs11`");
    }

    #[cfg(feature = "pkcs11")]
    fn load_pkcs11_cert(&self, uri: &str) -> Result<X509> {
        crate::transport::pkcs11::load_certificate(uri)
    }

    #[cfg(not(feature = "pkcs11"))]
    fn load_pkcs11_cert(&self, _uri: &str) -> Result<X509> {
        bail!("PKCS#11 certificates require building with `--features pkcs11`");
    }

    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Open a new TCP+TLS connection to the gateway, enforcing verification.
    pub async fn connect(&self) -> Result<SslStream<TcpStream>> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        if let Some(ca) = &self.ca_file {
            builder
                .set_ca_file(ca)
                .map_err(|e| anyhow::anyhow!("Failed to load CA file {:?}: {}", ca, e))?;
        }
        self.configure_builder(&mut builder)?;

        let state = Arc::new(Mutex::new(CertState {
            chain_ok: true,
            leaf_digest: None,
        }));
        let cb_state = state.clone();

        // Always return `true` so the handshake completes; record what real PKI
        // validation would have concluded and the leaf digest, then decide below.
        builder.set_verify_callback(SslVerifyMode::PEER, move |preverify_ok, ctx| {
            let mut st = cb_state.lock().unwrap();
            if !preverify_ok {
                st.chain_ok = false;
            }
            if ctx.error_depth() == 0
                && let Some(cert) = ctx.current_cert()
            {
                st.leaf_digest = Some(cert_sha256_hex(cert));
            }
            true
        });

        let connector = builder.build();
        let tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let ssl = connector.configure()?.into_ssl(&self.host)?;
        let mut stream = SslStream::new(ssl, tcp)?;

        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

        let st = state.lock().unwrap();
        let digest = st.leaf_digest.clone().unwrap_or_default();

        if !digest.is_empty() && self.trusted.contains(&digest) {
            tracing::debug!("Gateway certificate trusted via pinned digest {}", digest);
            return Ok(stream);
        }
        if st.chain_ok {
            return Ok(stream);
        }

        tracing::error!("Gateway certificate validation failed and its digest is not whitelisted.");
        tracing::error!("  sha256 digest: {}", digest);
        tracing::error!("  If you trust it, rerun with: --trusted-cert {}", digest);
        tracing::error!("  or add to your config file: trusted-cert = {}", digest);
        bail!("gateway certificate not trusted");
    }
}
