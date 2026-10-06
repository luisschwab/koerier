//! TLS configuration for LND's self-signed server certificate.

use std::sync::Arc;

use rustls::CertificateError;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::Error;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::crypto::verify_tls12_signature;
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;

/// Trust only the configured LND certificate, including certificates marked as CAs.
///
/// The certificate itself identifies the server instead of a CA chain, hostname, or
/// validity period. Handshake signatures still prove possession of its private key.
pub(crate) fn pinned_client_config(certificate: CertificateDer<'static>) -> Result<ClientConfig, Error> {
    let provider = rustls::crypto::ring::default_provider();
    let verifier = PinnedCertificateVerifier {
        certificate,
        algorithms: provider.signature_verification_algorithms,
    };

    Ok(ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// Authenticate LND by an exact certificate match and verified handshake signatures.
#[derive(Debug)]
struct PinnedCertificateVerifier {
    /// The trusted server certificate loaded from the configured file.
    certificate: CertificateDer<'static>,
    /// Signature algorithms supplied by the ring crypto provider.
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() != self.certificate.as_ref() {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use rustls::ServerConfig;
    use rustls::ServerConnection;
    use rustls::StreamOwned;
    use rustls::SupportedProtocolVersion;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject;

    use super::*;

    const CERTIFICATE: &[u8] = include_bytes!("../tests/fixtures/lnd-test-cert.pem");
    const OTHER_CERTIFICATE: &[u8] = include_bytes!("../tests/fixtures/other-test-cert.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/lnd-test-key.pem");

    async fn request_to_server(certificate: &[u8], version: &'static SupportedProtocolVersion) -> bool {
        let server_config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(certificate).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte)?;
                request.push(byte[0]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")?;
            stream.flush()
        });

        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(
                pinned_client_config(CertificateDer::from_pem_slice(CERTIFICATE).unwrap()).unwrap(),
            )
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let response = client.get(format!("https://{address}/")).send().await;
        let accepted = match response {
            Ok(response) => {
                assert_eq!(response.status(), reqwest::StatusCode::OK);
                assert_eq!(response.text().await.unwrap(), "OK");
                true
            }
            Err(error) => {
                assert!(error.is_connect(), "{error:?}");
                false
            }
        };
        assert_eq!(server.join().unwrap().is_ok(), accepted);
        accepted
    }

    #[tokio::test]
    async fn accepts_pinned_ca_certificate() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            assert!(request_to_server(CERTIFICATE, version).await);
        }
    }

    #[tokio::test]
    async fn rejects_different_certificate_with_the_same_key() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            assert!(!request_to_server(OTHER_CERTIFICATE, version).await);
        }
    }
}
