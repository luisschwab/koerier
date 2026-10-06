use core::error;
use core::fmt;
use std::io;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;

/// Errors from file access, LND requests, image processing, and JSON serialization.
#[derive(Debug)]
pub(crate) enum KoerierError {
    /// Error reading file from the file system.
    FsError(io::Error),
    /// Error parsing PEM certificate from LND.
    CertError(reqwest::Error),
    /// Error fetching payment request from LND.
    Lnd(String),
    /// Error opening image from the file system.
    Image(image::error::ImageError),
    /// Error serializing into JSON.
    Json(serde_json::Error),
}

impl fmt::Display for KoerierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FsError(e) => write!(f, "Error reading {e} from the file system"),
            Self::CertError(_) => write!(f, "Error parsing PEM certificate"),
            Self::Lnd(msg) => write!(f, "Error fetching payment request from LND: {msg}"),
            Self::Image(e) => write!(f, "Error opening image: {e}"),
            Self::Json(e) => write!(f, "Error serializing into JSON: {e}"),
        }
    }
}

impl error::Error for KoerierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FsError(e) => Some(e),
            Self::CertError(e) => Some(e),
            Self::Lnd(_) => None,
            Self::Image(e) => Some(e),
            Self::Json(e) => Some(e),
        }
    }
}

impl From<io::Error> for KoerierError {
    fn from(e: io::Error) -> Self {
        Self::FsError(e)
    }
}

impl From<reqwest::Error> for KoerierError {
    fn from(e: reqwest::Error) -> Self {
        Self::CertError(e)
    }
}

impl From<image::error::ImageError> for KoerierError {
    fn from(e: image::error::ImageError) -> Self {
        Self::Image(e)
    }
}

impl From<serde_json::Error> for KoerierError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl IntoResponse for KoerierError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}
