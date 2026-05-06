//! TLS transport implementation for NETCONF over TLS (RFC 7589).
//!
//! Connects to a NETCONF device over TLS (default port 6513) and provides
//! byte-stream read/write access to the TLS socket. Supports both server-only
//! and mutual TLS authentication.

use async_trait::async_trait;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::TransportError;
use crate::transport::Transport;

/// Configuration for establishing a TLS transport (RFC 7589).
///
/// # Examples
///
/// Server-only TLS (verify server cert, no client cert):
/// ```rust,no_run
/// use rustnetconf::transport::tls::TlsConfig;
///
/// let config = TlsConfig {
///     host: "10.0.0.1".into(),
///     server_name: Some("router.example.com".into()),
///     ..Default::default()
/// };
/// ```
///
/// Mutual TLS (client + server certs):
/// ```rust,no_run
/// use rustnetconf::transport::tls::TlsConfig;
///
/// let config = TlsConfig {
///     host: "10.0.0.1".into(),
///     ca_cert: Some("ca.pem".into()),
///     client_cert: Some("client.pem".into()),
///     client_key: Some("client-key.pem".into()),
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Device hostname or IP address.
    pub host: String,
    /// TLS port (default: 6513 per RFC 7589).
    pub port: u16,
    /// Path to a custom CA certificate (PEM) for server verification.
    /// When `None`, the system's default root CA bundle is used.
    pub ca_cert: Option<PathBuf>,
    /// Path to the client certificate (PEM) for mutual TLS authentication.
    pub client_cert: Option<PathBuf>,
    /// Path to the client private key (PEM) for mutual TLS authentication.
    pub client_key: Option<PathBuf>,
    /// Override the SNI server name used during the TLS handshake.
    /// Defaults to `host` if not set. Useful when connecting by IP address
    /// but the server certificate contains a hostname.
    pub server_name: Option<String>,
    /// Accept invalid server certificates (**INSECURE**).
    ///
    /// Suitable for lab environments with self-signed certificates.
    /// A warning is logged when this mode is used.
    pub danger_accept_invalid_certs: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 6513,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            server_name: None,
            danger_accept_invalid_certs: false,
        }
    }
}

/// TLS transport for NETCONF sessions (RFC 7589).
pub struct TlsTransport {
    stream: TlsStream<TcpStream>,
}

impl TlsTransport {
    /// Connect to a NETCONF device over TLS.
    ///
    /// After the TLS handshake completes, the NETCONF hello exchange begins
    /// immediately (no subsystem request like SSH).
    pub async fn connect(config: &TlsConfig) -> Result<Self, TransportError> {
        let tls_config = build_client_config(config)?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        let sni = config
            .server_name
            .as_deref()
            .unwrap_or(&config.host);

        let server_name = ServerName::try_from(sni.to_string()).map_err(|e| {
            TransportError::Tls(format!(
                "invalid server name '{sni}': {e}. Use server_name to set a valid hostname, \
                 or set danger_accept_invalid_certs for lab environments"
            ))
        })?;

        let tcp = TcpStream::connect((&*config.host, config.port))
            .await
            .map_err(|e| {
                TransportError::Connect(format!(
                    "TCP connect to {}:{} failed: {e}",
                    config.host, config.port
                ))
            })?;

        let stream = connector.connect(server_name, tcp).await.map_err(|e| {
            TransportError::Tls(format!(
                "TLS handshake with {}:{} failed: {e}",
                config.host, config.port
            ))
        })?;

        tracing::info!(
            host = %config.host,
            port = config.port,
            "TLS connection established"
        );

        Ok(Self { stream })
    }
}

#[async_trait]
impl Transport for TlsTransport {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.stream
            .write_all(data)
            .await
            .map_err(TransportError::Io)?;
        self.stream
            .flush()
            .await
            .map_err(TransportError::Io)?;
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let n = self
            .stream
            .read(buf)
            .await
            .map_err(TransportError::Io)?;
        Ok(n)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.stream
            .shutdown()
            .await
            .map_err(TransportError::Io)?;
        Ok(())
    }
}

/// Build a `rustls::ClientConfig` from a `TlsConfig`.
fn build_client_config(config: &TlsConfig) -> Result<rustls::ClientConfig, TransportError> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &config.ca_cert {
        let certs = load_pem_certs(ca_path)?;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                TransportError::Tls(format!("failed to add CA certificate: {e}"))
            })?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    let mut tls_config = if let (Some(cert_path), Some(key_path)) =
        (&config.client_cert, &config.client_key)
    {
        let certs = load_pem_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| TransportError::Tls(format!("client certificate error: {e}")))?
    } else if config.client_cert.is_some() || config.client_key.is_some() {
        return Err(TransportError::Tls(
            "both client_cert and client_key must be specified for mutual TLS".to_string(),
        ));
    } else {
        builder.with_no_client_auth()
    };

    if config.danger_accept_invalid_certs {
        tracing::warn!(
            "accepting invalid TLS certificates — \
             disable danger_accept_invalid_certs for production use"
        );
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(DangerousVerifier));
    }

    Ok(tls_config)
}

/// Load PEM-encoded certificates from a file.
fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| {
            TransportError::Tls(format!(
                "failed to open certificate file '{}': {e}",
                path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            TransportError::Tls(format!(
                "failed to parse PEM certificates from '{}': {e}",
                path.display()
            ))
        })?;

    if certs.is_empty() {
        return Err(TransportError::Tls(format!(
            "no certificates found in '{}'",
            path.display()
        )));
    }

    Ok(certs)
}

/// Load a PEM-encoded private key from a file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TransportError> {
    let key = PrivateKeyDer::from_pem_file(path).map_err(|e| {
        TransportError::Tls(format!(
            "failed to load private key from '{}': {e}",
            path.display()
        ))
    })?;

    Ok(key)
}

/// Certificate verifier that accepts all certificates (INSECURE).
///
/// Used only when `danger_accept_invalid_certs` is enabled for lab environments
/// with self-signed certificates.
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_defaults() {
        let config = TlsConfig::default();
        assert_eq!(config.port, 6513);
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
        assert!(config.server_name.is_none());
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_build_client_config_server_only() {
        let config = TlsConfig {
            host: "10.0.0.1".into(),
            ..Default::default()
        };
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_client_config_missing_key() {
        let config = TlsConfig {
            host: "10.0.0.1".into(),
            client_cert: Some("cert.pem".into()),
            // client_key intentionally missing
            ..Default::default()
        };
        let result = build_client_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("both client_cert and client_key"));
    }

    #[test]
    fn test_build_client_config_missing_cert() {
        let config = TlsConfig {
            host: "10.0.0.1".into(),
            client_key: Some("key.pem".into()),
            // client_cert intentionally missing
            ..Default::default()
        };
        let result = build_client_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("both client_cert and client_key"));
    }

    #[test]
    fn test_build_client_config_danger_accept_invalid() {
        let config = TlsConfig {
            host: "10.0.0.1".into(),
            danger_accept_invalid_certs: true,
            ..Default::default()
        };
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_pem_certs_nonexistent_file() {
        let result = load_pem_certs(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to open certificate file"));
    }

    #[test]
    fn test_load_private_key_nonexistent_file() {
        let result = load_private_key(Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to open key file"));
    }
}
