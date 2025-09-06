use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum KoerierError {
    /// Error reading file from the file system.
    #[error("Error reading {0} from the file system")]
    FsError(#[from] std::io::Error),

    /// Error parsing PEM certificate from LND.
    #[error("Error parsing PEM certificate")]
    CertError(#[from] reqwest::Error),

    /// Error fetching payment request from LND.
    #[error("Error fetching payment request from LND: {0}")]
    Lnd(String),

    /// Error opening image from the file system.
    #[error("Error opening image: {0}")]
    Image(#[from] image::error::ImageError),

    /// Error serializing into JSON.
    #[error("Error serializing into JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl IntoResponse for KoerierError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", self)).into_response()
    }
}
