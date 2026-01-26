use crate::error::KoerierError;
use log::{debug, error, info};
use nostr_sdk::prelude::*;

/// Validates a zap request event (kind 9734) according to NIP-57.
///
/// Required checks:
/// - Event kind must be 9734
/// - Event must have a valid signature
/// - Must have required tags: 'relays', 'amount', 'lnurl', 'p'
/// - Amount tag must match the requested amount
pub fn validate_zap_request(
    event_json: &str,
    requested_amount_msats: usize,
) -> Result<Event, KoerierError> {
    // Parse the event from JSON
    let event: Event = serde_json::from_str(event_json).map_err(|e| {
        error!("Failed to parse zap request JSON: {}", e);
        KoerierError::ZapValidation(format!("Invalid event JSON: {}", e))
    })?;

    // Verify the event kind is 9734 (Zap Request)
    if event.kind != Kind::from(9734) {
        error!("Invalid event kind: expected 9734, got {}", event.kind);
        return Err(KoerierError::ZapValidation(format!(
            "Invalid event kind: expected 9734, got {}",
            event.kind
        )));
    }

    // Verify the event signature
    event.verify().map_err(|e| {
        error!("Failed to verify zap request signature: {}", e);
        KoerierError::ZapValidation(format!("Invalid signature: {}", e))
    })?;

    // Check for required tags
    let has_relays = event.tags.iter().any(|t| {
        let tag_vec = (*t).clone().to_vec();
        tag_vec.first().map(|s| s.as_str()) == Some("relays")
    });
    let amount_tag = event.tags.iter().find(|t| {
        let tag_vec = (*t).clone().to_vec();
        tag_vec.first().map(|s| s.as_str()) == Some("amount")
    });
    let has_lnurl = event
        .tags
        .iter()
        .find(|t| {
            let tag_vec = (*t).clone().to_vec();
            tag_vec.first().map(|s| s.as_str()) == Some("lnurl")
        })
        .is_some();
    let has_p = event.tags.iter().any(|t| t.kind() == TagKind::p());

    if !has_relays {
        error!("Zap request missing 'relays' tag");
        return Err(KoerierError::ZapValidation(
            "Missing 'relays' tag".to_string(),
        ));
    }

    if !has_lnurl {
        error!("Zap request missing 'lnurl' tag");
        return Err(KoerierError::ZapValidation(
            "Missing 'lnurl' tag".to_string(),
        ));
    }

    if !has_p {
        error!("Zap request missing 'p' tag");
        return Err(KoerierError::ZapValidation("Missing 'p' tag".to_string()));
    }

    // Verify the amount tag matches the requested amount
    if let Some(amount_tag) = amount_tag {
        let tag_vec = amount_tag.clone().to_vec();
        if let Some(amount_str) = tag_vec.get(1) {
            let tag_amount_msats: usize = amount_str.as_str().parse().map_err(|e| {
                error!("Failed to parse amount tag: {}", e);
                KoerierError::ZapValidation(format!("Invalid amount tag: {}", e))
            })?;

            if tag_amount_msats != requested_amount_msats {
                error!(
                    "Amount mismatch: tag says {} msats, query param says {} msats",
                    tag_amount_msats, requested_amount_msats
                );
                return Err(KoerierError::ZapValidation(format!(
                    "Amount mismatch: tag says {} msats, query param says {} msats",
                    tag_amount_msats, requested_amount_msats
                )));
            }
        }
    } else {
        error!("Zap request missing 'amount' tag");
        return Err(KoerierError::ZapValidation(
            "Missing 'amount' tag".to_string(),
        ));
    }

    info!("Zap request validated successfully");
    debug!("Zap request event: {:?}", event);

    Ok(event)
}

/// Extracts relay URLs from a zap request event.
pub fn extract_relays(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| {
            let tag_vec = (*t).clone().to_vec();
            tag_vec.first().map(|s| s.as_str()) == Some("relays")
        })
        .filter_map(|t| {
            let vec = (*t).clone().to_vec();
            if vec.len() > 1 {
                Some(vec[1].to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Creates a zap receipt event (kind 9735) according to NIP-57.
pub async fn create_zap_receipt(
    zap_request: &Event,
    bolt11_invoice: &str,
    recipient_keys: &Keys,
) -> Result<Event, KoerierError> {
    // Build the zap receipt event
    let event_builder = EventBuilder::new(
        Kind::from(9735),
        "", // Empty content for zap receipts
    )
    // Add the bolt11 tag with the paid invoice
    .tag(Tag::custom(
        TagKind::Custom(std::borrow::Cow::Borrowed("bolt11")),
        vec![bolt11_invoice],
    ))
    // Add the description tag containing the original zap request JSON
    .tag(Tag::custom(
        TagKind::Custom(std::borrow::Cow::Borrowed("description")),
        vec![&serde_json::to_string(zap_request).map_err(|e| {
            error!("Failed to serialize zap request: {}", e);
            KoerierError::ZapReceipt(format!("Failed to serialize zap request: {}", e))
        })?],
    ))
    // Copy the 'p' tag from the zap request (recipient)
    .tags(
        zap_request
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::p())
            .cloned(),
    )
    // Copy the 'e' tag if present (zapped event)
    .tags(
        zap_request
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::e())
            .cloned(),
    )
    // Copy the 'a' tag if present (zapped addressable event)
    .tags(
        zap_request
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::a())
            .cloned(),
    );

    // Sign the event
    let event = event_builder.sign_with_keys(recipient_keys).map_err(|e| {
        error!("Failed to sign zap receipt: {}", e);
        KoerierError::ZapReceipt(format!("Failed to sign zap receipt: {}", e))
    })?;

    info!("Created zap receipt event: {}", event.id);

    Ok(event)
}

/// Publishes a zap receipt to the specified relays.
pub async fn publish_zap_receipt(
    event: Event,
    relay_urls: Vec<String>,
) -> Result<(), KoerierError> {
    if relay_urls.is_empty() {
        info!("No relays specified, skipping zap receipt publication");
        return Ok(());
    }

    info!("Publishing zap receipt to {} relays", relay_urls.len());

    // Create a new client
    let client = Client::new(Keys::generate());

    // Add relays
    for url in &relay_urls {
        match client.add_relay(url).await {
            Ok(_) => debug!("Added relay: {}", url),
            Err(e) => error!("Failed to add relay {}: {}", url, e),
        }
    }

    // Connect to relays
    client.connect().await;

    // Publish the event
    match client.send_event(event).await {
        Ok(_) => {
            info!("Successfully published zap receipt to relays");
            Ok(())
        }
        Err(e) => {
            error!("Failed to publish zap receipt: {}", e);
            Err(KoerierError::ZapReceipt(format!(
                "Failed to publish: {}",
                e
            )))
        }
    }
}
