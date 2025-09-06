use core::net::SocketAddr;
use std::{fs, io::Cursor, process, sync::Arc};

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

mod error;
mod lnd;

pub(crate) const ENDPOINT_LNURLP: &str = "/.well-known/lnurlp/{user}";
pub(crate) const ENDPOINT_CALLBACK: &str = "/lnurlp/callback";

/// TOML configuration file path CLI argument.
#[derive(Parser)]
#[command(name = "koerier")]
#[command(about = "A lightning address server for LND")]
pub(crate) struct Cli {
    #[arg(
        short = 'c',
        long = "config",
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
}

/// URL parameters that need to be read from the callback request: `amount`.
///
/// https://<domain>/<ENDPOINT_CALLBACK>?`amount`=<amount as milli-satoshis>
#[derive(Deserialize)]
pub(crate) struct CallbackParams {
    /// Amount, in milli satoshis.
    pub(crate) amount: usize,
}

/// The JSON response from the LNURLP request.
#[derive(Debug, Serialize)]
pub(crate) struct LnurlpResponse {
    /// The metadata field, which must contain a description and can contain a base64-encoded PNG or JPEG image.
    pub(crate) metadata: String,
    /// The mandatory "payRequest" tag.
    pub(crate) tag: String,
    /// The minimum invoice amount, in satoshis.
    #[serde(rename = "minSendable")]
    pub(crate) min_sendable: u64,
    /// The maximum invocie amount, in satoshis.
    #[serde(rename = "maxSendable")]
    pub(crate) max_sendable: u64,
    /// The URL the wallet must make a request with the `amount` parameter to for the invoice.
    pub(crate) callback: String,
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

    // Push a base64 image to the metadata, if the path is specified.
    if let Some(image) = state.koerier.image_path.clone() {
        let image = match image::open(&image) {
            Ok(png_image) => png_image,
            Err(e) => {
                error!("Error opening image at {}: {}", image, e);
                process::exit(1);
            }
        };

        let mut png_buffer = Vec::new();
        let mut cursor = Cursor::new(&mut png_buffer);

        // Convert all image formats to PNG.
        match image.write_to(&mut cursor, ImageFormat::Png) {
            Ok(_) => {}
            Err(e) => {
                error!("Error writing image to buffer: {}", e);
                process::exit(1);
            }
        }

        // Encode PNG to base64 and push it to the metadata array.
        let png_base64 = general_purpose::STANDARD.encode(&png_buffer);
        metadata.push(["image/png;base64".to_string(), png_base64]);
    }

    let response = LnurlpResponse {
        metadata: serde_json::to_string(&metadata)?,
        tag: "payRequest".to_string(),
        min_sendable: state.lnd.min_invoice_amount,
        max_sendable: state.lnd.max_invoice_amount,
        callback: format!("{}{}", state.koerier.domain, ENDPOINT_CALLBACK),
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
async fn fetch_invoice(
    State(state): State<Arc<AxumState>>,
    Query(params): Query<CallbackParams>,
) -> Result<String, KoerierError> {
    info!(
        "Received GET {}?amount={}",
        ENDPOINT_CALLBACK, params.amount
    );

    // Create a client to make REST requests to LND.
    let client = match state.lnd.create_client() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create reqwest client with LND's certificate: {e}");
            return Err(e);
        }
    };

    // LUD06 spec expects milli satoshis, but LND expects satoshis.
    let invoice_value = params.amount / 1000;

    // Compute the `description_hash` value, defined as the
    // SHA256 digest of the UTF-8 serialization of the description JSON array.
    // TODO(@luisschwab): is this correct?
    let metadata = json!([["text/plain", state.koerier.description]]);
    let mut hasher = Sha256::new();
    hasher.update(metadata.to_string().as_bytes());
    let description_hash = hasher.finalize().to_vec();

    // Try fetching the invoice from LND, and return it to the caller.
    let response_json = match state
        .lnd
        .fetch_invoice(client, invoice_value, description_hash)
        .await
    {
        Ok(invoice) => {
            info!(
                "Responded to GET {}?amount={}",
                ENDPOINT_CALLBACK, params.amount
            );
            info!("Invoice: {}", invoice);
            let success_response = PaymentRequestResponse {
                payment_request: invoice,
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

/// Read configuration params from `koerier.toml`.
fn parse_config(config_path: String) -> (Koerier, Lnd) {
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

    info!("Successfully parsed configuration from `{config_path}`");

    debug!("");
    debug!("[kourier]");
    debug!("domain = {}", koerier.domain);
    debug!("bind_address = {}", koerier.bind_address);
    debug!("description = {}", koerier.description);
    debug!("image_path = {:#?}", koerier.image_path);
    debug!("[lnd]");
    debug!("rest_host = {}", lnd.rest_host);
    debug!("tls_cert_path = {}", lnd.tls_cert_path);
    debug!("invoice_macaroon_path = {}", lnd.invoice_macaroon_path);
    debug!("min_invoice_amount = {}", lnd.min_invoice_amount);
    debug!("max_invoice_amount = {}", lnd.max_invoice_amount);
    debug!("invoice_expiry_sec = {}", lnd.invoice_expiry_sec);
    debug!("");

    (koerier, lnd)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args = Cli::parse();

    let (koerier, lnd) = parse_config(args.config);

    let state = Arc::new(AxumState {
        koerier: koerier.clone(),
        lnd,
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
