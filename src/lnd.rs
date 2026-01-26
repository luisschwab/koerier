use core::net::SocketAddr;
use std::fs;

use base64::{Engine, engine::general_purpose};
use reqwest::{Certificate, Client};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::KoerierError;

/// Response from creating an LND invoice.
#[derive(Clone, Debug)]
pub(crate) struct InvoiceResponse {
    /// The bolt11 payment request string.
    pub(crate) payment_request: String,
    /// The payment hash in hex format.
    pub(crate) payment_hash: String,
}

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
    ) -> Result<InvoiceResponse, KoerierError> {
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

        let payment_request = body
            .get("payment_request")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                KoerierError::Lnd("No `payment_request` in LND's response".to_string())
            })?;

        // Extract r_hash (base64) and convert to hex
        let r_hash_base64 = body
            .get("r_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KoerierError::Lnd("No `r_hash` in LND's response".to_string()))?;

        let payment_hash_bytes = general_purpose::STANDARD
            .decode(r_hash_base64)
            .map_err(|e| KoerierError::Lnd(format!("Failed to decode r_hash: {}", e)))?;
        let payment_hash = hex::encode(payment_hash_bytes);

        Ok(InvoiceResponse {
            payment_request: payment_request.to_string(),
            payment_hash,
        })
    }

    /// Check if a specific invoice has been settled.
    pub(crate) async fn is_invoice_settled(
        &self,
        client: &Client,
        payment_hash: &str,
    ) -> Result<bool, KoerierError> {
        let url = format!("https://{}/v1/invoice/{}", &self.rest_host, payment_hash);

        let response = client
            .get(&url)
            .header("Grpc-Metadata-macaroon", self.hex_encoded_macaroon()?)
            .send()
            .await?;

        let body: serde_json::Value = response.json().await?;

        // Check the state field - "SETTLED" means the invoice has been paid
        let state = body.get("state").and_then(|s| s.as_str()).unwrap_or("");

        Ok(state == "SETTLED")
    }

    /// Poll for settled invoices from the pending list.
    /// Returns a list of payment hashes that have been settled.
    pub(crate) async fn poll_settled_invoices(
        &self,
        client: &Client,
        payment_hashes: Vec<String>,
    ) -> Vec<String> {
        let mut settled = Vec::new();

        for payment_hash in payment_hashes {
            match self.is_invoice_settled(client, &payment_hash).await {
                Ok(true) => {
                    settled.push(payment_hash);
                }
                Ok(false) => {
                    // Not settled yet, continue
                }
                Err(e) => {
                    log::error!("Failed to check invoice status for {}: {}", payment_hash, e);
                }
            }
        }

        settled
    }
}
