use core::net::SocketAddr;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, Query, State},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use image::ImageFormat;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

use crate::error::KoerierError;
use crate::lnd::Lnd;
use crate::zap_storage::ZapStorage;

mod error;
mod lnd;
mod zap;
mod zap_storage;

pub(crate) const ENDPOINT_LNURLP: &str = "/.well-known/lnurlp/{user}";
pub(crate) const ENDPOINT_CALLBACK: &str = "/lnurlp/callback";

/// TOML configuration file path CLI argument.
#[derive(Parser)]
#[command(name = "koerier")]
#[command(about = "A lightning address server for LND")]
pub(crate) struct Cli {
    #[arg(
        long = "config",
        short = 'c',
        help = "The path to the TOML configuration file"
    )]
    pub(crate) config: String,
}

/// Koerier configuration parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Koerier {
    /// The address where `koerier` will be bound to.
    pub(crate) bind_address: SocketAddr,
    /// The domain used for the callback.
    pub(crate) domain: String,
    /// The description returned in the metadata field of the response.
    pub(crate) description: String,
    /// Optional: the path of the image returned in the metadata field of the response.
    pub(crate) image_path: Option<String>,
    /// Optional: Nostr private key in hex format for signing zap receipts.
    /// If not provided, zap receipts will not be generated.
    pub(crate) nostr_privkey: Option<String>,
}

/// State used in for the Axum router.
///
/// Koerier parameters: `bind_address`, `domain`, `description`, `image_path`,
/// LND parameters: `rest_host`, `invoice_macaroon_path`,
/// `tls_cert_path`, `min_invoice_amount`, `max_invocie_amount`, `invoice_expiry_sec`.
#[derive(Clone)]
pub(crate) struct AxumState {
    /// Koerier parameters.
    koerier: Koerier,
    /// LND parameters and methods.
    lnd: Lnd,
    /// Storage for pending zap requests.
    zap_storage: ZapStorage,
}

/// URL parameters that need to be read from the callback request: `amount` and optional `nostr`.
///
/// https://<domain>/<ENDPOINT_CALLBACK>?`amount`=<amount as milli-satoshis>&`nostr`=<zap request event JSON>
#[derive(Deserialize)]
pub(crate) struct CallbackParams {
    /// Amount, in milli satoshis.
    pub(crate) amount: usize,
    /// Optional Nostr zap request event (kind 9734) as URL-encoded JSON.
    pub(crate) nostr: Option<String>,
}

/// The JSON response from the LNURLP request.
#[derive(Debug, Serialize)]
pub(crate) struct LnurlpResponse {
    /// The metadata field, which must contain a description and can contain a base64-encoded PNG
    /// or JPEG image.
    pub(crate) metadata: String,
    /// The mandatory "payRequest" tag.
    pub(crate) tag: String,
    /// The minimum invoice amount, in milli-satoshis.
    #[serde(rename = "minSendable")]
    pub(crate) min_sendable: u64,
    /// The maximum invocie amount, in milli-satoshis.
    #[serde(rename = "maxSendable")]
    pub(crate) max_sendable: u64,
    /// The URL the wallet must make a request with the `amount` parameter to for the invoice.
    pub(crate) callback: String,
    /// Whether this server allows Nostr zaps (NIP-57).
    #[serde(rename = "allowsNostr", skip_serializing_if = "Option::is_none")]
    pub(crate) allows_nostr: Option<bool>,
    /// The Nostr public key in hex format for zap receipts (NIP-57).
    #[serde(rename = "nostrPubkey", skip_serializing_if = "Option::is_none")]
    pub(crate) nostr_pubkey: Option<String>,
}

/// The JSON response to the callback request.
#[derive(Debug, Serialize)]
pub(crate) struct PaymentRequestResponse {
    /// bech32-encoded lightning invoice.
    #[serde(rename = "pr")]
    pub(crate) payment_request: String,
    /// Empty array of route hints (legacy compatibility?)
    pub(crate) routes: Vec<String>,
}

/// An error response, per LUD06.
#[derive(Debug, Serialize)]
pub(crate) struct KoerierErrorResponse {
    /// The response status. Must be "ERROR".
    pub(crate) status: String,
    /// The reason for the error. Arbitrary.
    pub(crate) reason: String,
}

/// Response to the caller as per [LUD06-3](https://github.com/lnurl/luds/blob/luds/06.md#pay-to-static-qrnfclink):
/// ```json
/// {
///    "callback": string, // The URL from LN SERVICE which will accept the pay request parameters
///    "maxSendable": number, // Max millisatoshi amount LN SERVICE is willing to receive
///    "minSendable": number, // Min millisatoshi amount LN SERVICE is willing to receive, can not be less than 1 or more than `maxSendable`
///    "metadata": string, // Metadata json which must be presented as raw string here, this is required to pass signature verification at a later step
///    "tag": "payRequest" // Type of LNURL
/// }
/// ```
async fn return_params(
    State(state): State<Arc<AxumState>>,
    Path(user): Path<String>,
) -> Result<String, KoerierError> {
    info!("Received GET /.well-known/lnurlp/{}", user);

    let mut metadata: Vec<[String; 2]> =
        vec![["text/plain".to_string(), state.koerier.description.clone()]];

    // Push a base64-encode image to the metadata, if the path is specified.
    if let Some(image_path) = state.koerier.image_path.clone() {
        let image_path: PathBuf = PathBuf::from(&image_path);
        let base64_image: String = get_base64_image(&image_path)?;

        metadata.push(["image/png;base64".to_string(), base64_image]);
    }

    // LND returns the amount in sats, but we must return it milli-sats.
    let min_sendable = state.lnd.min_invoice_amount * 1000;
    let max_sendable = state.lnd.max_invoice_amount * 1000;

    // If nostr_privkey is configured, enable zap support and derive pubkey
    let (allows_nostr, nostr_pubkey) = if let Some(ref privkey_hex) = state.koerier.nostr_privkey {
        match nostr_sdk::prelude::SecretKey::from_hex(privkey_hex) {
            Ok(secret_key) => {
                let keys = nostr_sdk::prelude::Keys::new(secret_key);
                let pubkey = keys.public_key().to_hex();
                (Some(true), Some(pubkey))
            }
            Err(e) => {
                error!("Failed to parse nostr_privkey: {}", e);
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let response = LnurlpResponse {
        metadata: serde_json::to_string(&metadata)?,
        tag: "payRequest".to_string(),
        min_sendable,
        max_sendable,
        callback: format!("{}{}", state.koerier.domain, ENDPOINT_CALLBACK),
        allows_nostr,
        nostr_pubkey,
    };

    info!("Responded to GET /.well-known/lnurlp/{}", user);
    Ok(serde_json::to_string(&response)?)
}

/// Response to the caller as per [LUD06-6](https://github.com/lnurl/luds/blob/luds/06.md#pay-to-static-qrnfclink):
/// ```json
/// {
///     pr: string, // bech32-serialized lightning invoice
///     routes: [] // an empty array
/// }
/// ```
///
/// Also supports NIP-57 Zap requests when the `nostr` parameter is provided.
async fn fetch_invoice(
    State(state): State<Arc<AxumState>>,
    Query(params): Query<CallbackParams>,
) -> Result<String, KoerierError> {
    let zap_request_info = if params.nostr.is_some() {
        " (zap request)"
    } else {
        ""
    };
    info!(
        "Received GET {}?amount={}{}",
        ENDPOINT_CALLBACK, params.amount, zap_request_info
    );

    // Create a client to make REST requests to LND.
    let client = match state.lnd.create_client() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create reqwest client with LND's certificate: {e}");
            return Err(e);
        }
    };

    // Check that the requested invoice amount respects the boundaries set by `minSendable` and
    // `maxSendable`.
    let amount = params.amount;
    // Convert boundaries from milli-satoshi to satoshi.
    let min_amount = state.lnd.min_invoice_amount * 1000;
    let max_amount = state.lnd.max_invoice_amount * 1000;
    if amount < min_amount as usize || amount > max_amount as usize {
        error!(
            "Caller requested an invoice amount that is out of bounds: {amount} ∌ [{min_amount}, {max_amount}]"
        );
        let error_response = KoerierErrorResponse {
            status: "ERROR".to_string(),
            reason: format!(
                "The amount must be between {min_amount} and {max_amount} milli-satoshis, you requested {amount}"
            ),
        };

        return Ok(serde_json::to_string(&error_response)?);
    }

    // If a nostr parameter is provided, validate the zap request
    let validated_zap_request = if let Some(ref nostr_json) = params.nostr {
        match zap::validate_zap_request(nostr_json, params.amount) {
            Ok(event) => {
                info!("Zap request validated successfully");
                Some(event)
            }
            Err(e) => {
                error!("Zap request validation failed: {}", e);
                let error_response = KoerierErrorResponse {
                    status: "ERROR".to_string(),
                    reason: format!("Invalid zap request: {}", e),
                };
                return Ok(serde_json::to_string(&error_response)?);
            }
        }
    } else {
        None
    };

    // Compute the `description_hash` value.
    // For zap requests, use the zap request JSON as per NIP-57.
    // Otherwise, use the metadata JSON array as per LUD06.
    let description_string = if let Some(ref nostr_json) = params.nostr {
        nostr_json.clone()
    } else {
        json!([["text/plain", state.koerier.description]]).to_string()
    };

    let mut hasher = Sha256::new();
    hasher.update(description_string.as_bytes());
    let description_hash = hasher.finalize().to_vec();

    // Convert the amount from milli-satoshis to satoshis.
    let invoice_amount = amount / 1000;

    // Try fetching the invoice from LND and return it to the caller, or return an error.
    let response_json = match state
        .lnd
        .fetch_invoice(client, invoice_amount, description_hash)
        .await
    {
        Ok(invoice_response) => {
            info!(
                "Responded to GET {}?amount={}",
                ENDPOINT_CALLBACK, params.amount
            );
            info!("Invoice: {}", invoice_response.payment_request);
            info!("Payment hash: {}", invoice_response.payment_hash);

            // Store zap request for automatic receipt generation when payment is received
            if let Some(zap_request) = validated_zap_request {
                if state.koerier.nostr_privkey.is_some() {
                    info!("Storing zap request for automatic receipt generation");
                    state
                        .zap_storage
                        .store(
                            invoice_response.payment_hash.clone(),
                            zap_request,
                            invoice_response.payment_request.clone(),
                        )
                        .await;
                    info!(
                        "Zap request stored. Receipt will be generated automatically upon payment."
                    );
                } else {
                    error!(
                        "Zap request received but no nostr_privkey configured. Cannot generate zap receipt."
                    );
                }
            }

            let success_response = PaymentRequestResponse {
                payment_request: invoice_response.payment_request,
                routes: vec![],
            };

            serde_json::to_string(&success_response)?
        }
        Err(_) => {
            let error_response = KoerierErrorResponse {
                status: "ERROR".to_string(),
                reason: "Failed to fetch invoice from LND".to_string(),
            };
            error!("Failed to fetch invoice from LND");
            error!(
                "Responded to GET {}?amount={} with an error",
                ENDPOINT_CALLBACK, params.amount
            );
            serde_json::to_string(&error_response)?
        }
    };

    Ok(response_json)
}

/// Read configuration parameters from the TOML configuration file.
fn parse_config(config_path: String) -> Result<(Koerier, Lnd), KoerierError> {
    let config_str = match fs::read_to_string(&config_path) {
        Ok(config_str) => config_str,
        Err(_) => {
            error!("Failed to open `{config_path}`. Does the file exist?");
            process::exit(1);
        }
    };
    let config: toml::Value = match toml::from_str(&config_str) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to parse TOML from `{config_path}`: {e}");
            process::exit(1);
        }
    };
    let koerier: Koerier = match config["koerier"].clone().try_into() {
        Ok(koerier) => koerier,
        Err(e) => {
            error!("Failed to parse `[koerier]` section from `{config_path}`: {e}");
            process::exit(1);
        }
    };
    let lnd: Lnd = match config["lnd"].clone().try_into() {
        Ok(lnd) => lnd,
        Err(e) => {
            error!("Failed to parse `[lnd]` section from `{config_path}`: {e}");
            process::exit(1);
        }
    };

    // Try to parse the image to catch any errors on startup.
    if let Some(image_path) = &koerier.image_path {
        let image_path: PathBuf = PathBuf::from(&image_path);
        let _base64_png = match get_base64_image(&image_path) {
            Ok(_) => (),
            Err(_) => process::exit(1),
        };
    };

    info!("Successfully parsed configuration from `{config_path}`");

    debug!("");
    debug!("[kourier]");
    debug!("domain = {}", koerier.domain);
    debug!("bind_address = {}", koerier.bind_address);
    debug!("description = {}", koerier.description);
    debug!("image_path = {:#?}", koerier.image_path);
    debug!(
        "nostr_privkey = {}",
        if koerier.nostr_privkey.is_some() {
            "configured (hidden)"
        } else {
            "not configured"
        }
    );
    debug!("[lnd]");
    debug!("rest_host = {}", lnd.rest_host);
    debug!("tls_cert_path = {}", lnd.tls_cert_path);
    debug!("invoice_macaroon_path = {}", lnd.invoice_macaroon_path);
    debug!("min_invoice_amount = {}", lnd.min_invoice_amount);
    debug!("max_invoice_amount = {}", lnd.max_invoice_amount);
    debug!("invoice_expiry_sec = {}", lnd.invoice_expiry_sec);
    debug!("");

    Ok((koerier, lnd))
}

/// Get a base64-encoded image [`String`] from a [`PathBuf`].
fn get_base64_image(image_path: &PathBuf) -> Result<String, KoerierError> {
    let image = match image::open(&image_path) {
        Ok(png) => png,
        Err(e) => {
            error!(
                "Failed to open image with path path {}: {}",
                image_path.display(),
                e
            );
            return Err(KoerierError::Image(e));
        }
    };

    let mut png_buffer: Vec<u8> = Vec::new();
    let mut cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut png_buffer);
    match image.write_to(&mut cursor, ImageFormat::Png) {
        Ok(_) => {}
        Err(e) => {
            error!("Error writing image to buffer: {}", e);
            return Err(KoerierError::Image(e));
        }
    }

    let base64_png: String = general_purpose::STANDARD.encode(&png_buffer);

    Ok(base64_png)
}

/// Background task that monitors LND for invoice settlements and generates zap receipts.
async fn monitor_invoices_and_generate_zaps(
    lnd: Lnd,
    zap_storage: ZapStorage,
    nostr_privkey: Option<String>,
) {
    use tokio::time::{Duration, sleep};

    // Only run if nostr_privkey is configured
    let nostr_privkey = match nostr_privkey {
        Some(key) => key,
        None => {
            info!("Nostr private key not configured, zap receipt generation disabled");
            return;
        }
    };

    // Parse the nostr keys
    let keys = match nostr_sdk::prelude::SecretKey::from_hex(&nostr_privkey) {
        Ok(secret_key) => nostr_sdk::prelude::Keys::new(secret_key),
        Err(e) => {
            error!(
                "Failed to parse nostr_privkey, zap receipts disabled: {}",
                e
            );
            return;
        }
    };

    info!("Starting invoice monitoring for automatic zap receipt generation");

    // Create LND client
    let client = match lnd.create_client() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create LND client for invoice monitoring: {}", e);
            return;
        }
    };

    info!("Polling for invoice settlements every 5 seconds");

    // Poll for settled invoices every 5 seconds
    loop {
        sleep(Duration::from_secs(5)).await;

        // Get list of pending payment hashes
        let pending_count = zap_storage.len().await;
        if pending_count == 0 {
            continue;
        }

        debug!("Checking {} pending zap invoices", pending_count);

        // We need to get all pending payment hashes
        // Since we can't iterate the HashMap directly, we'll check each as we poll
        // For now, let's use a simple approach: store payment hashes separately
        // Actually, let me check invoices by iterating through the internal storage
        // For simplicity, let's poll LND's recent invoices endpoint instead

        // Get recent invoices from LND
        let url = format!(
            "https://{}/v1/invoices?num_max_invoices=100&reversed=true",
            lnd.rest_host
        );
        let response = match client
            .get(&url)
            .header(
                "Grpc-Metadata-macaroon",
                match lnd.hex_encoded_macaroon() {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to encode macaroon: {}", e);
                        continue;
                    }
                },
            )
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to fetch recent invoices: {}", e);
                continue;
            }
        };

        let body: serde_json::Value = match response.json().await {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to parse invoices response: {}", e);
                continue;
            }
        };

        // Check each invoice
        if let Some(invoices) = body.get("invoices").and_then(|i| i.as_array()) {
            for invoice in invoices {
                let state = invoice.get("state").and_then(|s| s.as_str());
                if state == Some("SETTLED") {
                    // Extract payment hash
                    if let Some(r_hash) = invoice.get("r_hash").and_then(|h| h.as_str()) {
                        if let Ok(hash_bytes) =
                            base64::engine::general_purpose::STANDARD.decode(r_hash)
                        {
                            let payment_hash = hex::encode(hash_bytes);

                            // Check if we have a pending zap for this payment hash
                            if let Some(pending_zap) = zap_storage.take(&payment_hash).await {
                                info!("Invoice settled: {}", payment_hash);
                                info!(
                                    "Found zap request for settled invoice, generating zap receipt"
                                );

                                // Generate zap receipt
                                match zap::create_zap_receipt(
                                    &pending_zap.zap_request,
                                    &pending_zap.invoice,
                                    &keys,
                                )
                                .await
                                {
                                    Ok(zap_receipt) => {
                                        info!("Zap receipt created: {}", zap_receipt.id);

                                        // Extract relays from the zap request
                                        let relays = zap::extract_relays(&pending_zap.zap_request);
                                        info!("Publishing zap receipt to {} relays", relays.len());

                                        // Publish the zap receipt
                                        match zap::publish_zap_receipt(zap_receipt, relays).await {
                                            Ok(_) => {
                                                info!(
                                                    "Zap receipt published successfully for payment_hash: {}",
                                                    payment_hash
                                                );
                                            }
                                            Err(e) => {
                                                error!("Failed to publish zap receipt: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to create zap receipt: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args = Cli::parse();

    let (koerier, lnd) = parse_config(args.config).unwrap();

    // Create zap storage
    let zap_storage = ZapStorage::new();

    // Start invoice monitoring task in background if nostr_privkey is configured
    if koerier.nostr_privkey.is_some() {
        let lnd_clone = lnd.clone();
        let zap_storage_clone = zap_storage.clone();
        let nostr_privkey_clone = koerier.nostr_privkey.clone();

        tokio::spawn(async move {
            monitor_invoices_and_generate_zaps(lnd_clone, zap_storage_clone, nostr_privkey_clone)
                .await;
        });
    }

    let state = Arc::new(AxumState {
        koerier: koerier.clone(),
        lnd,
        zap_storage,
    });

    let router: Router = Router::new()
        .route(ENDPOINT_LNURLP, get(return_params))
        .route(ENDPOINT_CALLBACK, get(fetch_invoice))
        .with_state(state);

    let listener = match TcpListener::bind(koerier.bind_address).await {
        Ok(listener) => {
            info!("koerier is bound and listening at {}", koerier.bind_address);
            listener
        }
        Err(e) => {
            error!("koerier failed to bind to {}: {}", koerier.bind_address, e);
            process::exit(1);
        }
    };

    let _ = match axum::serve(listener, router).await {
        Ok(_) => {}
        Err(e) => {
            error!("axum failed to serve: {}", e);
            process::exit(1);
        }
    };
}
