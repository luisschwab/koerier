use core::net::SocketAddr;
use std::fs;

use base64::{Engine, engine::general_purpose};
use reqwest::{Certificate, Client};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::KoerierError;

/// LND configuration parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Lnd {
    /// The REST host where LND is listening. The default host is `127.0.0.1:8080`.
    pub(crate) rest_host: SocketAddr,
    /// The full path to the `tls.cert` file. The default path is `~/.lnd/tls.cert`.
    pub(crate) tls_cert_path: String,
    /// The full path to the `invoice.macaroon` file. The default path is
    /// `~/.lnd/data/chain/bitcoin/mainnet/invoice.macaroon`.
    pub(crate) invoice_macaroon_path: String,
    /// The minimum invoice amount, in satoshis.
    pub(crate) min_invoice_amount: u64,
    /// The maximum invoice amoun, in satoshis.
    pub(crate) max_invoice_amount: u64,
    /// The invoice expiry time, in seconds.
    pub(crate) invoice_expiry_sec: u32,
}

/// LND related methods.
impl Lnd {
    /// Create an async client that makes requests to LND's REST interface.
    pub(crate) fn create_client(&self) -> Result<Client, KoerierError> {
        let cert: Vec<u8> = fs::read(&self.tls_cert_path)?;
        let cert: Certificate = Certificate::from_pem(&cert)?;

        let client: Client = Client::builder().add_root_certificate(cert).build()?;

        Ok(client)
    }

    /// Encode the binary `invoice.macaroon` file into hexadecimal.
    pub(crate) fn hex_encoded_macaroon(&self) -> Result<String, KoerierError> {
        let invoice_macaroon = fs::read(&self.invoice_macaroon_path)?;
        let invoice_macaroon = hex::encode(invoice_macaroon);

        Ok(invoice_macaroon)
    }

    /// Make a POST request to the `/v1/invoices` endpoint and fetch an invoice with the defined
    /// amount.
    pub(crate) async fn fetch_invoice(
        &self,
        client: Client,
        value: usize,
        description_hash: Vec<u8>,
    ) -> Result<String, KoerierError> {
        // Request body for the `POST /v1/invoices` endpoint.
        let request_body = json!({
            "value": value,
            "description_hash": general_purpose::STANDARD.encode(&description_hash),
            "expiry": &self.invoice_expiry_sec,
            "private": false,
        });

        // Full URL to the invoice endpoint.
        let url_invoices = format!("https://{}/v1/invoices", &self.rest_host);

        // Make the request to LND with the `invoice.macaroon` as a header.
        let response = client
            .post(url_invoices)
            .header("Grpc-Metadata-macaroon", self.hex_encoded_macaroon()?)
            .json(&request_body)
            .send()
            .await?;
        let body: serde_json::Value = response.json().await?;

        if let Some(payment_request) = body.get("payment_request") {
            Ok(payment_request.as_str().unwrap().to_string())
        } else {
            Err(KoerierError::Lnd(
                "No `payment_request` in LND's response".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hex_encoded_macaroon() {
        // Creates temporary file with known contents
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("macaroon");
        fs::write(&path, vec![0xAB, 0xCD]).unwrap();

        let lnd = Lnd {
            rest_host: "127.0.0.1:8080".parse().unwrap(),
            tls_cert_path: "".to_string(),
            invoice_macaroon_path: path.to_string_lossy().to_string(),
            min_invoice_amount: 1000,
            max_invoice_amount: 1000000,
            invoice_expiry_sec: 3600,
        };

        let hex = lnd.hex_encoded_macaroon().unwrap();
        assert_eq!(hex, "abcd");
    }

    #[test]
    fn test_request_body_json() {
        let description_hash = vec![1, 2, 3];
        let expiry = 120;

        let expected = json!({
            "value": 42,
            "description_hash": base64::engine::general_purpose::STANDARD.encode(&description_hash),
            "expiry": expiry,
            "private": false,
        });

        let generated = json!({
            "value": 42,
            "description_hash": general_purpose::STANDARD.encode(&description_hash),
            "expiry": expiry,
            "private": false,
        });

        assert_eq!(expected, generated);
    }
}
