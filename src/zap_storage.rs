use log::{debug, info};
use nostr_sdk::prelude::Event;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory storage for pending zap requests, keyed by payment hash (hex).
#[derive(Clone, Debug)]
pub struct ZapStorage {
    pending: Arc<RwLock<HashMap<String, PendingZap>>>,
}

/// A pending zap request waiting for payment.
#[derive(Clone, Debug)]
pub struct PendingZap {
    /// The validated zap request event (kind 9734).
    pub zap_request: Event,
    /// The bolt11 invoice string.
    pub invoice: String,
}

impl ZapStorage {
    /// Creates a new empty zap storage.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Stores a pending zap request associated with a payment hash.
    pub async fn store(&self, payment_hash: String, zap_request: Event, invoice: String) {
        let mut pending = self.pending.write().await;
        debug!("Storing zap request for payment_hash: {}", payment_hash);
        pending.insert(
            payment_hash,
            PendingZap {
                zap_request,
                invoice,
            },
        );
        info!("Total pending zaps: {}", pending.len());
    }

    /// Retrieves and removes a pending zap request by payment hash.
    pub async fn take(&self, payment_hash: &str) -> Option<PendingZap> {
        let mut pending = self.pending.write().await;
        let result = pending.remove(payment_hash);
        if result.is_some() {
            debug!("Retrieved zap request for payment_hash: {}", payment_hash);
            info!("Total pending zaps: {}", pending.len());
        }
        result
    }

    /// Returns the number of pending zap requests.
    pub async fn len(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Checks if there are any pending zap requests.
    pub async fn is_empty(&self) -> bool {
        self.pending.read().await.is_empty()
    }
}

impl Default for ZapStorage {
    fn default() -> Self {
        Self::new()
    }
}
