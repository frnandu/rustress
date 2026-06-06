use actix_cors::Cors;
use actix_files as fs;
use actix_web::web::Query;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, cookie::Cookie, web};
use log::{info, warn};
use nostr::prelude::*;
use nostr_sdk::{
    Client, Event as SdkEvent, EventBuilder as SdkEventBuilder, Keys as SdkKeys, Kind,
    SecretKey as SdkSecretKey, Tag, TagStandard,
};
use nwc::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::env as std_env;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep, timeout};

mod db;

use crate::db::{
    Invoice, ZAP_RECEIPT_STATUS_FAILED, ZAP_RECEIPT_STATUS_PENDING, ZAP_RECEIPT_STATUS_PUBLISHED,
    add_prism_split, create_user, delete_prism_splits_by_user_id,
    delete_user_by_username_and_domain, get_all_users_with_secret, get_db_pool,
    get_invoice_by_payment_hash, get_pending_zap_receipt_invoices, get_prism_splits_by_user_id,
    get_user_by_username_and_domain, insert_invoice, mark_invoice_settled, run_migrations,
    update_invoice_metadata_with_zap_receipt, update_invoice_zap_receipt_state,
    update_user_details, update_user_prism_status,
};

#[derive(Clone)]
struct AppConfig {
    admin_password: String,
}

const MAX_ZAP_RECEIPT_RELAYS: usize = 5;
const ZAP_PUBLISH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ZAP_PUBLISH_TIMEOUT: Duration = Duration::from_secs(20);
const ZAP_RECEIPT_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const ZAP_RECEIPT_RETRY_BATCH: i64 = 100;
const NWC_LISTENER_SESSION_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Serialize)]
struct PublishAttemptResult {
    event_id: String,
    attempted_relays: Vec<String>,
    success_relays: Vec<String>,
    failed_relays: HashMap<String, String>,
}

struct ZapReceiptPublisher {
    client: Client,
    keys: SdkKeys,
    publish_lock: Mutex<()>,
}

fn generate_admin_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..12)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// Admin authentication middleware
fn check_admin_auth(req: &HttpRequest, admin_password: &str) -> bool {
    if let Some(auth_cookie) = req.cookie("admin_auth") {
        auth_cookie.value() == admin_password
    } else {
        false
    }
}

#[derive(Deserialize)]
struct AdminLoginRequest {
    password: String,
}

fn get_lnurl_metadata(username: &str, domain: &str) -> String {
    serde_json::to_string(&vec![
        vec![
            "text/identifier",
            format!("{}@{}", username, domain).as_str(),
        ],
        vec!["text/plain", format!("Sats for {}", username).as_str()],
    ])
    .unwrap()
}

// Implement proper npub to hex conversion using nostr crate
fn npub_to_hex(npub: &str) -> Option<String> {
    if npub.starts_with("npub") {
        // Use nostr crate's PublicKey to decode npub
        match nostr::PublicKey::from_str(npub) {
            Ok(pubkey) => Some(pubkey.to_string()),
            Err(_) => None,
        }
    } else {
        // Already in hex format
        Some(npub.to_string())
    }
}

impl ZapReceiptPublisher {
    fn new(private_key: &str) -> Result<Self, String> {
        let secret = SdkSecretKey::from_str(private_key)
            .map_err(|e| format!("Invalid NIP57_PRIVATE_KEY: {e}"))?;
        let keys = SdkKeys::new(secret);
        Ok(Self {
            client: Client::new(keys.clone()),
            keys,
            publish_lock: Mutex::new(()),
        })
    }

    fn public_key_hex(&self) -> String {
        self.keys.public_key().to_string()
    }

    async fn publish_zap_receipt(
        &self,
        event: &SdkEvent,
        requested_relays: &[String],
    ) -> Result<PublishAttemptResult, String> {
        let _guard = self.publish_lock.lock().await;

        let attempted_relays = requested_relays
            .iter()
            .take(MAX_ZAP_RECEIPT_RELAYS)
            .cloned()
            .collect::<Vec<_>>();
        if attempted_relays.is_empty() {
            return Err("No relays available for zap receipt publish".to_string());
        }

        let mut send_targets = Vec::new();
        let mut failed_relays = HashMap::new();
        for relay_url in &attempted_relays {
            match self.client.add_write_relay(relay_url).await {
                Ok(_) => {}
                Err(e) => {
                    failed_relays.insert(relay_url.clone(), format!("add relay failed: {e}"));
                    continue;
                }
            }

            match self
                .client
                .try_connect_relay(relay_url, ZAP_PUBLISH_CONNECT_TIMEOUT)
                .await
            {
                Ok(_) => send_targets.push(relay_url.clone()),
                Err(e) => {
                    failed_relays.insert(relay_url.clone(), format!("connect failed: {e}"));
                }
            }
        }

        let mut success_relays = Vec::new();
        if !send_targets.is_empty() {
            match timeout(
                ZAP_PUBLISH_TIMEOUT,
                self.client
                    .send_event_to(send_targets.iter().cloned(), event),
            )
            .await
            {
                Ok(Ok(output)) => {
                    success_relays = output.success.iter().map(|url| url.to_string()).collect();
                    for (url, err) in output.failed {
                        failed_relays.insert(url.to_string(), err);
                    }
                }
                Ok(Err(e)) => {
                    for relay_url in &send_targets {
                        failed_relays
                            .entry(relay_url.clone())
                            .or_insert_with(|| format!("send failed: {e}"));
                    }
                }
                Err(_) => {
                    for relay_url in &send_targets {
                        failed_relays
                            .entry(relay_url.clone())
                            .or_insert_with(|| "send timeout".to_string());
                    }
                }
            }
        }

        for relay_url in &attempted_relays {
            let _ = self.client.disconnect_relay(relay_url).await;
            let _ = self.client.force_remove_relay(relay_url).await;
        }

        Ok(PublishAttemptResult {
            event_id: event.id.to_string(),
            attempted_relays,
            success_relays,
            failed_relays,
        })
    }
}

fn extract_zap_request(metadata: &str) -> Option<serde_json::Value> {
    let metadata_json = serde_json::from_str::<serde_json::Value>(metadata).ok()?;
    metadata_json.get("nostr").cloned()
}

fn extract_zap_receipt_relays(zap_request: &serde_json::Value) -> Vec<String> {
    let mut relays = Vec::new();
    let Some(tags) = zap_request.get("tags").and_then(|tags| tags.as_array()) else {
        return relays;
    };

    for tag in tags {
        let Some(items) = tag.as_array() else {
            continue;
        };
        if items.first() != Some(&serde_json::json!("relays")) {
            continue;
        }

        for relay in items.iter().skip(1).filter_map(|value| value.as_str()) {
            let relay = relay.trim().trim_end_matches('/').to_string();
            if !relay.is_empty() && !relays.contains(&relay) {
                relays.push(relay);
            }
            if relays.len() >= MAX_ZAP_RECEIPT_RELAYS {
                return relays;
            }
        }
    }

    relays
}

fn extract_first_tag_value(zap_request: &serde_json::Value, tag_name: &str) -> Option<String> {
    zap_request
        .get("tags")
        .and_then(|tags| tags.as_array())
        .and_then(|tags| {
            tags.iter().find_map(|tag| {
                let items = tag.as_array()?;
                if items.first() == Some(&serde_json::json!(tag_name)) {
                    items.get(1)?.as_str().map(|value| value.to_string())
                } else {
                    None
                }
            })
        })
}

fn build_zap_receipt_event(
    publisher: &ZapReceiptPublisher,
    invoice: &Invoice,
) -> Result<Option<(SdkEvent, Vec<String>)>, String> {
    let metadata = invoice.metadata.as_deref().unwrap_or("");
    let Some(zap_request) = extract_zap_request(metadata) else {
        return Ok(None);
    };

    let relays = extract_zap_receipt_relays(&zap_request);
    if relays.is_empty() {
        return Err("Zap request does not include any relay targets".to_string());
    }

    let zapped_pubkey = extract_first_tag_value(&zap_request, "p")
        .ok_or_else(|| "Zap request is missing required 'p' tag".to_string())?;
    let zapped_pubkey = nostr_sdk::PublicKey::from_str(&zapped_pubkey)
        .map_err(|e| format!("Invalid 'p' tag pubkey: {e}"))?;

    let mut tags = vec![Tag::from_standardized_without_cell(TagStandard::Bolt11(
        invoice.payment_request.clone(),
    ))];

    if let Some(event_id) = extract_first_tag_value(&zap_request, "e") {
        let event_id = nostr_sdk::EventId::from_hex(&event_id)
            .map_err(|e| format!("Invalid 'e' tag event id: {e}"))?;
        tags.push(Tag::event(event_id));
    }

    if let Some(coordinate) = extract_first_tag_value(&zap_request, "a") {
        let tag = Tag::parse(vec!["a".to_string(), coordinate])
            .map_err(|e| format!("Invalid 'a' tag: {e}"))?;
        tags.push(tag);
    }

    tags.push(Tag::public_key(zapped_pubkey));
    tags.push(
        Tag::parse(vec![
            "description".to_string(),
            serde_json::to_string(&zap_request).map_err(|e| format!("Invalid zap request: {e}"))?,
        ])
        .map_err(|e| format!("Failed to build description tag: {e}"))?,
    );

    if let Some(preimage) = &invoice.preimage {
        tags.push(Tag::from_standardized_without_cell(TagStandard::Preimage(
            preimage.clone(),
        )));
    }

    let event = SdkEventBuilder::new(Kind::ZapReceipt, "")
        .tags(tags)
        .sign_with_keys(&publisher.keys)
        .map_err(|e| format!("Failed to sign zap receipt event: {e}"))?;

    Ok(Some((event, relays)))
}

async fn lnurlp(
    pool: web::Data<Arc<SqlitePool>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let username = path.into_inner();

    // Extract domain from Host header
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");

    // Remove port from host if present
    let domain = host.split(':').next().unwrap_or(host);

    let user = match get_user_by_username_and_domain(&pool, &username, domain).await {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"status": "ERROR", "reason": "User not found"}));
        }
    };

    let scheme = if req.connection_info().scheme() == "https" {
        "https"
    } else {
        "http"
    };
    let base_url = format!("{}://{}", scheme, host);

    let mut resp = serde_json::json!({
        "tag": "payRequest",
        "commentAllowed": 255,
        "callback": format!("{}/lnurlp/{}/callback", base_url, user.username),
        "minSendable": 1000,
        "maxSendable": 10000000000u64,
        "metadata": get_lnurl_metadata(&user.username, &user.domain),
        "payerData": {
            "name": {"mandatory": false},
            "email": {"mandatory": false},
            "pubkey": {"mandatory": false}
        }
    });
    // Add user's nostrPubkey (converted from npub to hex if needed)
    if let Some(_) = user.nostr_pubkey {
        // Use the NIP57_PRIVATE_KEY to derive the public key for nostrPubkey
        if let Ok(sk_str) = std::env::var("NIP57_PRIVATE_KEY") {
            if let Ok(sk) = SdkSecretKey::from_str(&sk_str) {
                let keys = SdkKeys::new(sk);
                let pubkey = keys.public_key();
                resp["nostrPubkey"] = serde_json::json!(pubkey.to_string());
                resp["allowsNostr"] = serde_json::json!(true);
            }
        }
    }
    HttpResponse::Ok().json(resp)
}

async fn nip05(
    pool: web::Data<Arc<SqlitePool>>,
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Some(username) = query.get("name") {
        // Extract domain from Host header
        let host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost:8080");
        // Remove port from host if present
        let domain = host.split(':').next().unwrap_or(host);

        let user_result = get_user_by_username_and_domain(&pool, username, domain).await;
        match user_result {
            Ok(user) => {
                let hex_pubkey = user
                    .nostr_pubkey
                    .as_ref()
                    .and_then(|npub| npub_to_hex(npub));
                HttpResponse::Ok().json(serde_json::json!({
                    "names": { user.username: hex_pubkey }
                }))
            }
            Err(_) => HttpResponse::Ok().json(serde_json::json!({"names": {}})),
        }
    } else {
        HttpResponse::Ok().json(serde_json::json!({"names": {}}))
    }
}

#[derive(Deserialize)]
struct AddUserRequest {
    connection_secret: Option<String>,
    username: Option<String>,
    nostr_pubkey: Option<String>,
    domain: String,
    is_prism: Option<bool>,
    prism_splits: Option<Vec<PrismSplitRequest>>,
}

#[derive(Deserialize, Clone)]
struct PrismSplitRequest {
    lightning_address: String,
    percentage: f64,
}

async fn lnurlp_callback(
    pool: web::Data<Arc<SqlitePool>>,
    req: HttpRequest,
    path: web::Path<String>,
    query: Query<HashMap<String, String>>,
) -> impl Responder {
    let username = path.into_inner();

    // Extract domain from Host header
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");

    // Remove port from host if present
    let domain = host.split(':').next().unwrap_or(host);

    let user = match get_user_by_username_and_domain(&pool, &username, domain).await {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"status": "ERROR", "reason": "User not found"}));
        }
    };
    let amount = match query.get("amount").and_then(|a| a.parse::<u64>().ok()) {
        Some(a) if a >= 1000 => a,
        _ => {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"status": "ERROR", "reason": "Invalid or missing amount"}),
            );
        }
    };
    let comment = query.get("comment").cloned().unwrap_or_default();
    let nostr = query.get("nostr").cloned();
    let payer_data = query.get("payerdata").cloned();
    let zap_request = nostr
        .as_ref()
        .and_then(|n| serde_json::from_str::<serde_json::Value>(n).ok());
    let description = zap_request
        .as_ref()
        .and_then(|z| z.get("content").and_then(|c| c.as_str()))
        .unwrap_or(&comment);

    // Check if user has NWC connection secret
    let nwc_secret = match &user.nwc_uri {
        Some(secret) => secret,
        None => {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"status": "ERROR", "reason": "User has no payment method configured"}),
            );
        }
    };

    // Parse the NWC URI
    let uri =
        match NostrWalletConnectURI::from_str(nwc_secret) {
            Ok(u) => u,
            Err(e) => return HttpResponse::InternalServerError().json(
                serde_json::json!({"status": "ERROR", "reason": format!("Invalid NWC URI: {}", e)}),
            ),
        };
    // Create the NWC client
    let nwc = NWC::new(uri);
    // Create the invoice request
    let request = MakeInvoiceRequest {
        amount,
        description: Some(description.to_string()),
        description_hash: None,
        expiry: None,
    };
    // Create the invoice
    let invoice =
        match nwc.make_invoice(request).await {
            Ok(i) => i,
            Err(e) => return HttpResponse::InternalServerError().json(
                serde_json::json!({"status": "ERROR", "reason": format!("Invoice error: {}", e)}),
            ),
        };
    let payment_request = invoice.invoice.clone();
    let payment_hash = invoice.payment_hash.clone();

    let metadata = serde_json::json!({
        "comment": comment,
        "payer_data": payer_data,
        "nostr": zap_request
    })
    .to_string();
    let invoice_rec = match insert_invoice(
        &pool,
        user.id,
        amount as i64,
        description,
        &payment_request,
        &payment_hash,
        &metadata,
    )
    .await
    {
        Ok(inv) => inv,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()}));
        }
    };

    // Use the request host to construct the base URL
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");
    let scheme = if req.connection_info().scheme() == "https" {
        "https"
    } else {
        "http"
    };
    let base_url = format!("{}://{}", scheme, host);

    HttpResponse::Ok().json(serde_json::json!({
        "verify": format!("{}/lnurlp/{}/verify/{}", base_url, user.username, invoice_rec.payment_hash),
        "routes": [],
        "pr": invoice_rec.payment_request
    }))
}

async fn lnurlp_verify(
    pool: web::Data<Arc<SqlitePool>>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (_username, payment_hash) = path.into_inner();
    let invoice = match get_invoice_by_payment_hash(&pool, &payment_hash).await {
        Ok(inv) => inv,
        Err(_) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"status": "ERROR", "reason": "Invoice not found"}));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "settled": invoice.settled_at.is_some(),
        "preimage": invoice.preimage,
        "pr": invoice.payment_request
    }))
}

// Helper function to process prism splits
async fn process_prism_payment(
    pool: &SqlitePool,
    user_id: i64,
    amount_msats: u64,
    nwc_uri: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!(
        "Starting prism payment processing for user {} with amount {} msats",
        user_id,
        amount_msats
    );

    // Get prism splits
    let splits = get_prism_splits_by_user_id(pool, user_id).await?;

    log::info!("Found {} prism splits for user {}", splits.len(), user_id);

    if splits.is_empty() {
        log::warn!("No prism splits configured for user {}, skipping", user_id);
        return Ok(()); // No splits, nothing to do
    }

    // Parse NWC URI
    log::info!("Parsing NWC URI for prism payments");
    let uri = NostrWalletConnectURI::from_str(nwc_uri)?;
    let nwc = NWC::new(uri);

    // Create HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // Process each split
    for split in splits {
        let split_amount_msats = ((amount_msats as f64) * (split.percentage / 100.0)) as u64;

        if split_amount_msats < 1000 {
            log::warn!(
                "Split amount too small ({} msats) for {}, skipping",
                split_amount_msats,
                split.lightning_address
            );
            continue;
        }

        log::info!(
            "Processing prism split: {}% ({} msats) to {}",
            split.percentage,
            split_amount_msats,
            split.lightning_address
        );

        // Process lightning address (username@domain)
        if split.lightning_address.contains('@') {
            let parts: Vec<&str> = split.lightning_address.split('@').collect();
            if parts.len() == 2 {
                let username = parts[0];
                let domain = parts[1];

                // Make LNURL request to get callback URL
                let lnurl_url = format!("https://{}/.well-known/lnurlp/{}", domain, username);
                log::info!("Fetching LNURL from: {}", lnurl_url);

                match timeout(Duration::from_secs(10), client.get(&lnurl_url).send()).await {
                    Ok(Ok(response)) => {
                        log::info!(
                            "Got LNURL response from {}, status: {}",
                            lnurl_url,
                            response.status()
                        );
                        match timeout(Duration::from_secs(5), response.json::<serde_json::Value>())
                            .await
                        {
                            Ok(Ok(lnurl_response)) => {
                                log::info!("Parsed LNURL response: {:?}", lnurl_response);
                                if let Some(callback) =
                                    lnurl_response.get("callback").and_then(|c| c.as_str())
                                {
                                    // Request invoice from callback
                                    let invoice_url =
                                        format!("{}?amount={}", callback, split_amount_msats);
                                    log::info!("Requesting invoice from callback: {}", invoice_url);

                                    match timeout(
                                        Duration::from_secs(10),
                                        client.get(&invoice_url).send(),
                                    )
                                    .await
                                    {
                                        Ok(Ok(inv_response)) => {
                                            log::info!(
                                                "Got invoice response, status: {}",
                                                inv_response.status()
                                            );
                                            match timeout(
                                                Duration::from_secs(5),
                                                inv_response.json::<serde_json::Value>(),
                                            )
                                            .await
                                            {
                                                Ok(Ok(inv_json)) => {
                                                    log::info!(
                                                        "Parsed invoice response: {:?}",
                                                        inv_json
                                                    );
                                                    if let Some(pr) =
                                                        inv_json.get("pr").and_then(|p| p.as_str())
                                                    {
                                                        log::info!(
                                                            "Got payment request: {}",
                                                            if pr.len() > 50 {
                                                                &pr[..50]
                                                            } else {
                                                                pr
                                                            }
                                                        );
                                                        // Pay the invoice using NWC
                                                        let pay_request = PayInvoiceRequest {
                                                            id: None,
                                                            invoice: pr.to_string(),
                                                            amount: None,
                                                        };
                                                        log::info!("Paying invoice via NWC...");
                                                        match timeout(
                                                            Duration::from_secs(30),
                                                            nwc.pay_invoice(pay_request),
                                                        )
                                                        .await
                                                        {
                                                            Ok(Ok(response)) => {
                                                                log::info!(
                                                                    "Successfully paid {} msats to {}, preimage: {:?}",
                                                                    split_amount_msats,
                                                                    split.lightning_address,
                                                                    response.preimage
                                                                );
                                                            }
                                                            Ok(Err(e)) => {
                                                                log::error!(
                                                                    "Failed to pay invoice to {}: {}",
                                                                    split.lightning_address,
                                                                    e
                                                                );
                                                            }
                                                            Err(_) => {
                                                                log::error!(
                                                                    "Timeout paying invoice to {}",
                                                                    split.lightning_address
                                                                );
                                                            }
                                                        }
                                                    } else {
                                                        log::error!(
                                                            "No 'pr' field in invoice response"
                                                        );
                                                    }
                                                }
                                                Ok(Err(e)) => {
                                                    log::error!(
                                                        "Failed to parse invoice JSON: {}",
                                                        e
                                                    );
                                                }
                                                Err(_) => {
                                                    log::error!(
                                                        "Timeout parsing invoice JSON response"
                                                    );
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            log::error!(
                                                "Failed to get invoice from {}: {}",
                                                invoice_url,
                                                e
                                            );
                                        }
                                        Err(_) => {
                                            log::error!(
                                                "Timeout getting invoice from {}",
                                                invoice_url
                                            );
                                        }
                                    }
                                } else {
                                    log::error!("No 'callback' field in LNURL response");
                                }
                            }
                            Ok(Err(e)) => {
                                log::error!("Failed to parse LNURL JSON: {}", e);
                            }
                            Err(_) => {
                                log::error!("Timeout parsing LNURL JSON response");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        log::error!(
                            "Failed to resolve lightning address {}: {}",
                            split.lightning_address,
                            e
                        );
                    }
                    Err(_) => {
                        log::error!(
                            "Timeout resolving lightning address {}",
                            split.lightning_address
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn invoice_contains_zap_request(invoice: &Invoice) -> bool {
    invoice
        .metadata
        .as_deref()
        .and_then(extract_zap_request)
        .is_some()
}

fn summarize_failed_relays(failed_relays: &HashMap<String, String>) -> Option<String> {
    if failed_relays.is_empty() {
        None
    } else {
        Some(
            failed_relays
                .iter()
                .map(|(relay, error)| format!("{relay}: {error}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

async fn process_zap_receipt_for_invoice(
    pool: &SqlitePool,
    publisher: &ZapReceiptPublisher,
    invoice: &Invoice,
) {
    let prepared = match build_zap_receipt_event(publisher, invoice) {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return,
        Err(error) => {
            warn!(
                "Failed to build zap receipt for payment_hash {}: {}",
                invoice.payment_hash, error
            );
            if let Err(db_error) = update_invoice_zap_receipt_state(
                pool,
                &invoice.payment_hash,
                invoice.zap_receipt_json.as_deref().unwrap_or(""),
                ZAP_RECEIPT_STATUS_FAILED,
                None,
                None,
                Some(&error),
                false,
            )
            .await
            {
                warn!(
                    "Failed to persist zap receipt build error for payment_hash {}: {}",
                    invoice.payment_hash, db_error
                );
            }
            return;
        }
    };

    let (event, relays) = prepared;
    let receipt_json = match serde_json::to_string(&event) {
        Ok(json) => json,
        Err(error) => {
            warn!(
                "Failed to serialize zap receipt event for payment_hash {}: {}",
                invoice.payment_hash, error
            );
            return;
        }
    };

    let publish_result = match publisher.publish_zap_receipt(&event, &relays).await {
        Ok(result) => result,
        Err(error) => {
            warn!(
                "Failed to publish zap receipt event {} for payment_hash {}: {}",
                event.id, invoice.payment_hash, error
            );
            if let Err(db_error) = update_invoice_zap_receipt_state(
                pool,
                &invoice.payment_hash,
                &receipt_json,
                ZAP_RECEIPT_STATUS_FAILED,
                None,
                None,
                Some(&error),
                false,
            )
            .await
            {
                warn!(
                    "Failed to persist zap receipt publish error for payment_hash {}: {}",
                    invoice.payment_hash, db_error
                );
            }
            return;
        }
    };

    let success_relays_json = serde_json::to_string(&publish_result.success_relays).ok();
    let failed_relays_json = serde_json::to_string(&publish_result.failed_relays).ok();
    let published = !publish_result.success_relays.is_empty();
    let last_error = summarize_failed_relays(&publish_result.failed_relays);
    let status = if published {
        ZAP_RECEIPT_STATUS_PUBLISHED
    } else {
        ZAP_RECEIPT_STATUS_FAILED
    };

    if let Err(error) = update_invoice_zap_receipt_state(
        pool,
        &invoice.payment_hash,
        &receipt_json,
        status,
        success_relays_json.as_deref(),
        failed_relays_json.as_deref(),
        last_error.as_deref(),
        published,
    )
    .await
    {
        warn!(
            "Failed to update zap receipt state for payment_hash {}: {}",
            invoice.payment_hash, error
        );
    }

    if published {
        info!(
            "Published zap receipt event {} for payment_hash {}. success_relays={:?} failed_relays={:?}",
            publish_result.event_id,
            invoice.payment_hash,
            publish_result.success_relays,
            publish_result.failed_relays
        );
        if let Err(error) =
            update_invoice_metadata_with_zap_receipt(pool, &invoice.payment_hash, &receipt_json)
                .await
        {
            warn!(
                "Failed to update invoice metadata with zap receipt for payment_hash {}: {}",
                invoice.payment_hash, error
            );
        }
    } else {
        warn!(
            "Zap receipt event {} was not accepted by any relay for payment_hash {}. attempted_relays={:?} failed_relays={:?}",
            publish_result.event_id,
            invoice.payment_hash,
            publish_result.attempted_relays,
            publish_result.failed_relays
        );
    }
}

async fn handle_invoice_settlement(
    pool: Arc<SqlitePool>,
    publisher: Option<Arc<ZapReceiptPublisher>>,
    user_id: i64,
    payment_hash: String,
    preimage: String,
    nwc_secret: String,
) {
    if let Err(error) = mark_invoice_settled(&pool, &payment_hash, &preimage).await {
        warn!(
            "Failed to mark invoice settled for user {} and payment_hash {}: {}",
            user_id, payment_hash, error
        );
    }

    let invoice = match get_invoice_by_payment_hash(&pool, &payment_hash).await {
        Ok(invoice) => invoice,
        Err(error) => {
            warn!(
                "Failed to get invoice by payment_hash {}: {}",
                payment_hash, error
            );
            return;
        }
    };

    let invoice_user_id = invoice.user_id;
    info!(
        "Payment notification from NWC owner (user {}), but invoice belongs to user {}",
        user_id, invoice_user_id
    );

    let invoice_user = match sqlx::query_as::<_, crate::db::User>(
        r#"SELECT id, nwc_uri, username, nostr_pubkey, domain, is_prism, created_at FROM users WHERE id = ?"#
    )
    .bind(invoice_user_id)
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(user) => user,
        Err(error) => {
            warn!("Failed to fetch invoice user {}: {}", invoice_user_id, error);
            return;
        }
    };

    info!(
        "Checking prism status: is_prism={} for invoice user {}",
        invoice_user.is_prism, invoice_user_id
    );
    if invoice_user.is_prism {
        let amount_msats = invoice.amount as u64;
        info!(
            "Invoice user {} is a prism, processing payment split for {} msats",
            invoice_user_id, amount_msats
        );
        if let Err(error) =
            process_prism_payment(&pool, invoice_user_id, amount_msats, &nwc_secret).await
        {
            warn!(
                "Failed to process prism payment for user {}: {}",
                invoice_user_id, error
            );
        } else {
            info!(
                "Successfully completed prism payment processing for user {}",
                invoice_user_id
            );
        }
    }

    if !invoice_contains_zap_request(&invoice) {
        return;
    }

    let Some(publisher) = publisher else {
        warn!(
            "Skipping zap receipt publish for payment_hash {} because NIP57 publisher is disabled",
            invoice.payment_hash
        );
        if let Err(error) = update_invoice_zap_receipt_state(
            pool.as_ref(),
            &invoice.payment_hash,
            invoice.zap_receipt_json.as_deref().unwrap_or(""),
            ZAP_RECEIPT_STATUS_PENDING,
            None,
            None,
            Some("NIP57 publisher disabled"),
            false,
        )
        .await
        {
            warn!(
                "Failed to persist pending zap receipt state for payment_hash {}: {}",
                invoice.payment_hash, error
            );
        }
        return;
    };

    process_zap_receipt_for_invoice(pool.as_ref(), publisher.as_ref(), &invoice).await;
}

async fn retry_pending_zap_receipts(pool: Arc<SqlitePool>, publisher: Arc<ZapReceiptPublisher>) {
    loop {
        match get_pending_zap_receipt_invoices(&pool, ZAP_RECEIPT_RETRY_BATCH).await {
            Ok(invoices) => {
                for invoice in invoices {
                    process_zap_receipt_for_invoice(pool.as_ref(), publisher.as_ref(), &invoice)
                        .await;
                }
            }
            Err(error) => warn!("Failed to load pending zap receipts: {}", error),
        }

        sleep(ZAP_RECEIPT_RETRY_INTERVAL).await;
    }
}

fn spawn_nwc_notification_listener(
    pool: Arc<SqlitePool>,
    publisher: Option<Arc<ZapReceiptPublisher>>,
    user_id: i64,
    secret: String,
) {
    tokio::spawn(async move {
        let secret_arc = Arc::new(secret);

        loop {
            let uri = match NostrWalletConnectURI::from_str(secret_arc.as_ref()) {
                Ok(u) => u,
                Err(e) => {
                    warn!("Invalid NWC URI for user {}: {}", user_id, e);
                    return;
                }
            };

            info!(
                "Starting NWC notification listener for user {} (wallet pubkey: {}, relays: {})",
                user_id,
                uri.public_key,
                uri.relays.len()
            );

            let nwc = NWC::new(uri);
            if let Err(e) = nwc.subscribe_to_notifications().await {
                warn!(
                    "Failed to subscribe to notifications for user {}: {}",
                    user_id, e
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }

            let pool_cloned = pool.clone();
            let secret_cloned = secret_arc.clone();
            let publisher_cloned = publisher.clone();
            let handle_future = nwc.handle_notifications(move |notification| {
                let pool = pool_cloned.clone();
                let nwc_secret = secret_cloned.clone();
                let publisher = publisher_cloned.clone();
                async move {
                    use nostr::nips::nip47::NotificationType;
                    if let NotificationType::PaymentReceived = notification.notification_type {
                        if let Ok(payment) = notification.to_pay_notification() {
                            let payment_hash = payment.payment_hash.clone();
                            let preimage = payment.preimage.clone();
                            let pool_clone = pool.clone();
                            let nwc_secret_clone = nwc_secret.as_ref().clone();
                            tokio::spawn(async move {
                                handle_invoice_settlement(
                                    pool_clone,
                                    publisher,
                                    user_id,
                                    payment_hash,
                                    preimage,
                                    nwc_secret_clone,
                                )
                                .await;
                            });
                        }
                    }
                    Ok::<bool, Box<dyn std::error::Error>>(false)
                }
            });

            match timeout(NWC_LISTENER_SESSION_TTL, handle_future).await {
                Ok(Ok(_)) => {
                    warn!(
                        "NWC notification stream ended for user {}, reconnecting",
                        user_id
                    );
                }
                Ok(Err(error)) => {
                    warn!(
                        "Error handling NWC notification for user {}: {}",
                        user_id, error
                    );
                }
                Err(_) => {
                    warn!(
                        "NWC notification listener session expired for user {}, reconnecting",
                        user_id
                    );
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn subscribe_nwc_notifications(
    pool: Arc<SqlitePool>,
    publisher: Option<Arc<ZapReceiptPublisher>>,
) {
    let users = match get_all_users_with_secret(&pool).await {
        Ok(u) => u,
        Err(e) => {
            warn!("Failed to load users for NWC subscription: {}", e);
            return;
        }
    };

    for user in users {
        let secret = match &user.nwc_uri {
            Some(s) => s.clone(),
            None => {
                warn!(
                    "User {} has no NWC connection secret, skipping notifications",
                    user.id
                );
                continue;
            }
        };

        spawn_nwc_notification_listener(pool.clone(), publisher.clone(), user.id, secret);
    }
}

// Admin authentication endpoints
async fn admin_login(
    config: web::Data<Arc<AppConfig>>,
    req: web::Json<AdminLoginRequest>,
) -> impl Responder {
    if req.password == config.admin_password {
        let cookie = Cookie::build("admin_auth", &config.admin_password)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::hours(24))
            .http_only(true)
            .finish();

        HttpResponse::Ok()
            .cookie(cookie)
            .json(serde_json::json!({"status": "OK", "message": "Login successful"}))
    } else {
        HttpResponse::Unauthorized()
            .json(serde_json::json!({"status": "ERROR", "reason": "Invalid password"}))
    }
}

async fn admin_interface(req: HttpRequest, config: web::Data<Arc<AppConfig>>) -> impl Responder {
    if !check_admin_auth(&req, &config.admin_password) {
        return HttpResponse::Unauthorized().body(include_str!("../static/login.html"));
    }

    match fs::NamedFile::open("static/admin.html") {
        Ok(file) => file.into_response(&req),
        Err(_) => HttpResponse::InternalServerError().body("Admin interface not found"),
    }
}

// Protected admin endpoints
async fn admin_users(
    req: HttpRequest,
    pool: web::Data<Arc<SqlitePool>>,
    config: web::Data<Arc<AppConfig>>,
) -> impl Responder {
    if !check_admin_auth(&req, &config.admin_password) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"status": "ERROR", "reason": "Authentication required"}));
    }

    match get_all_users_with_secret(&pool).await {
        Ok(users) => {
            let mut safe_users = Vec::new();

            for user in users {
                let mut user_json = serde_json::json!({
                    "id": user.id,
                    "username": user.username,
                    "nostr_pubkey": user.nostr_pubkey,
                    "domain": user.domain,
                    "is_prism": user.is_prism,
                    "created_at": user.created_at
                });

                // If prism, include splits
                if user.is_prism {
                    if let Ok(splits) = get_prism_splits_by_user_id(&pool, user.id).await {
                        user_json["prism_splits"] = serde_json::json!(splits);
                    }
                }

                safe_users.push(user_json);
            }

            HttpResponse::Ok().json(safe_users)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "ERROR",
            "reason": e.to_string()
        })),
    }
}

async fn admin_add_user(
    req: HttpRequest,
    pool: web::Data<Arc<SqlitePool>>,
    config: web::Data<Arc<AppConfig>>,
    publisher: web::Data<Option<Arc<ZapReceiptPublisher>>>,
    user_req: web::Json<AddUserRequest>,
) -> impl Responder {
    if !check_admin_auth(&req, &config.admin_password) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"status": "ERROR", "reason": "Authentication required"}));
    }

    let is_prism = user_req.is_prism.unwrap_or(false);

    // Validate based on prism or non-prism
    if is_prism {
        // Prism requires NWC with pay_invoice permission and splits
        let has_connection_secret = user_req
            .connection_secret
            .as_ref()
            .map_or(false, |s| !s.trim().is_empty());
        if !has_connection_secret {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": "Prism requires NWC connection string with pay_invoice permission"}));
        }

        let splits = match &user_req.prism_splits {
            Some(s) if !s.is_empty() => s,
            _ => return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": "Prism requires at least one split"})),
        };

        // Validate percentages
        let total_percentage: f64 = splits.iter().map(|s| s.percentage).sum();
        if total_percentage > 100.0 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": format!("Split percentages must not exceed 100, got {}", total_percentage)}));
        }

        // Validate each percentage is positive
        for split in splits {
            if split.percentage <= 0.0 || split.percentage > 100.0 {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"status": "ERROR", "reason": "Each split percentage must be between 0 and 100"}));
            }
        }
    } else {
        // Non-prism validation
        let has_connection_secret = user_req
            .connection_secret
            .as_ref()
            .map_or(false, |s| !s.trim().is_empty());
        let has_nostr_pubkey = user_req
            .nostr_pubkey
            .as_ref()
            .map_or(false, |s| !s.trim().is_empty());

        if !has_connection_secret && !has_nostr_pubkey {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": "At least one of 'connection_secret' (for LNURL) or 'nostr_pubkey' (for NIP-05) must be provided"}));
        }
    }

    let username = user_req
        .username
        .clone()
        .unwrap_or_else(|| format!("{}", rand::random::<u64>()));

    match create_user(
        &pool,
        user_req.connection_secret.as_deref(),
        &username,
        user_req.nostr_pubkey.as_deref(),
        &user_req.domain,
        is_prism,
    )
    .await
    {
        Ok(user) => {
            // If prism, add splits
            if is_prism {
                if let Some(splits) = &user_req.prism_splits {
                    for split in splits {
                        if let Err(e) = add_prism_split(
                            &pool,
                            user.id,
                            &split.lightning_address,
                            split.percentage,
                        )
                        .await
                        {
                            // Rollback by deleting user
                            let _ = delete_user_by_username_and_domain(
                                &pool,
                                &user.username,
                                &user.domain,
                            )
                            .await;
                            return HttpResponse::InternalServerError()
                                .json(serde_json::json!({"status": "ERROR", "reason": format!("Failed to add prism split: {}", e)}));
                        }
                    }
                }
            }

            if let Some(secret) = user_req.connection_secret.clone() {
                if !secret.trim().is_empty() {
                    spawn_nwc_notification_listener(
                        pool.get_ref().clone(),
                        publisher.get_ref().clone(),
                        user.id,
                        secret,
                    );
                }
            }

            let lightning_address = format!("{}@{}", user.username, user.domain);
            HttpResponse::Ok().json(
                serde_json::json!({"lightning_address": lightning_address, "is_prism": is_prism}),
            )
        }
        Err(e) => HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()})),
    }
}

async fn admin_delete_user(
    req: HttpRequest,
    pool: web::Data<Arc<SqlitePool>>,
    config: web::Data<Arc<AppConfig>>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !check_admin_auth(&req, &config.admin_password) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"status": "ERROR", "reason": "Authentication required"}));
    }

    let (username, domain) = path.into_inner();
    match delete_user_by_username_and_domain(&pool, &username, &domain).await {
        Ok(deleted) => {
            if deleted {
                HttpResponse::Ok().json(serde_json::json!({
                    "status": "OK",
                    "message": format!("User '{}'@'{}' deleted successfully", username, domain)
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "status": "ERROR",
                    "reason": format!("User '{}'@'{}' not found", username, domain)
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "ERROR",
            "reason": e.to_string()
        })),
    }
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    nwc_uri: Option<String>,
    nostr_pubkey: Option<String>,
    is_prism: bool,
    prism_splits: Option<Vec<PrismSplitRequest>>,
}

async fn admin_update_prism(
    req: HttpRequest,
    pool: web::Data<Arc<SqlitePool>>,
    config: web::Data<Arc<AppConfig>>,
    publisher: web::Data<Option<Arc<ZapReceiptPublisher>>>,
    path: web::Path<(String, String)>,
    user_req: web::Json<UpdateUserRequest>,
) -> impl Responder {
    if !check_admin_auth(&req, &config.admin_password) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"status": "ERROR", "reason": "Authentication required"}));
    }

    let (username, domain) = path.into_inner();

    // Get user
    let user = match get_user_by_username_and_domain(&pool, &username, &domain).await {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"status": "ERROR", "reason": "User not found"}));
        }
    };

    // Determine the effective NWC URI (use provided or keep existing)
    let effective_nwc_uri = user_req.nwc_uri.as_deref().or(user.nwc_uri.as_deref());

    // Validate prism configuration
    if user_req.is_prism {
        if effective_nwc_uri.is_none() {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": "Prism requires NWC connection string"}));
        }

        let splits = match &user_req.prism_splits {
            Some(s) if !s.is_empty() => s,
            _ => return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": "Prism requires at least one split"})),
        };

        // Validate percentages
        let total_percentage: f64 = splits.iter().map(|s| s.percentage).sum();
        if total_percentage > 100.0 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": format!("Split percentages must not exceed 100, got {}", total_percentage)}));
        }

        for split in splits {
            if split.percentage <= 0.0 || split.percentage > 100.0 {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"status": "ERROR", "reason": "Each split percentage must be between 0 and 100"}));
            }
        }
    }

    // Update user details (NWC URI and nostr_pubkey)
    if user_req.nwc_uri.is_some() || user_req.nostr_pubkey.is_some() {
        let nwc_to_update = user_req.nwc_uri.as_deref().or(user.nwc_uri.as_deref());
        let nostr_to_update = user_req
            .nostr_pubkey
            .as_deref()
            .or(user.nostr_pubkey.as_deref());

        if let Err(e) = update_user_details(&pool, user.id, nwc_to_update, nostr_to_update).await {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()}));
        }

        if let Some(new_secret) = &user_req.nwc_uri {
            if !new_secret.trim().is_empty() && user.nwc_uri.as_deref() != Some(new_secret.as_str())
            {
                spawn_nwc_notification_listener(
                    pool.get_ref().clone(),
                    publisher.get_ref().clone(),
                    user.id,
                    new_secret.clone(),
                );
            }
        }
    }

    // Update user prism status
    if let Err(e) = update_user_prism_status(&pool, user.id, user_req.is_prism).await {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()}));
    }

    // Delete existing splits
    if let Err(e) = delete_prism_splits_by_user_id(&pool, user.id).await {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()}));
    }

    // Add new splits if prism
    if user_req.is_prism {
        if let Some(splits) = &user_req.prism_splits {
            for split in splits {
                if let Err(e) =
                    add_prism_split(&pool, user.id, &split.lightning_address, split.percentage)
                        .await
                {
                    return HttpResponse::InternalServerError()
                        .json(serde_json::json!({"status": "ERROR", "reason": format!("Failed to add prism split: {}", e)}));
                }
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "OK",
        "message": format!("User configuration updated for '{}'@'{}'", username, domain)
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let pool: SqlitePool = get_db_pool().await;
    run_migrations(&pool).await;
    let pool = Arc::new(pool);

    let publisher: Option<Arc<ZapReceiptPublisher>> = match std_env::var("NIP57_PRIVATE_KEY") {
        Ok(private_key) => match ZapReceiptPublisher::new(&private_key) {
            Ok(publisher) => {
                let publisher = Arc::new(publisher);
                info!(
                    "Zap receipt publisher enabled with pubkey {}",
                    publisher.public_key_hex()
                );
                Some(publisher)
            }
            Err(error) => {
                warn!("Failed to initialize zap receipt publisher: {}", error);
                None
            }
        },
        Err(_) => {
            warn!("NIP57_PRIVATE_KEY not set, zap receipt publishing is disabled");
            None
        }
    };

    // Start NWC subscription after database is ready
    let pool_for_nwc = pool.clone();
    let publisher_for_nwc = publisher.clone();
    tokio::spawn(async move {
        subscribe_nwc_notifications(pool_for_nwc, publisher_for_nwc).await;
    });

    if let Some(publisher_for_retry) = publisher.clone() {
        let pool_for_retry = pool.clone();
        tokio::spawn(async move {
            retry_pending_zap_receipts(pool_for_retry, publisher_for_retry).await;
        });
    }

    // Get admin password from env var or generate one
    let admin_password = std_env::var("ADMIN_PASSWORD").unwrap_or_else(|_| {
        let generated = generate_admin_password();
        println!("🔐 GENERATED ADMIN PASSWORD: {}", generated);
        println!("💡 Save this password - it's required to access /admin");
        println!("💡 Or set ADMIN_PASSWORD environment variable to use a static password");
        generated
    });

    if std_env::var("ADMIN_PASSWORD").is_ok() {
        println!("🔐 Using ADMIN_PASSWORD from environment variable");
    }

    let config = Arc::new(AppConfig { admin_password });

    let bind_address = std_env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std_env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);
    info!("Starting server at {}:{}", bind_address, port);
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(publisher.clone()))
            .route("/lnurlp/{username}", web::get().to(lnurlp))
            .route("/.well-known/lnurlp/{username}", web::get().to(lnurlp))
            .route("/.well-known/nostr.json", web::get().to(nip05))
            .route(
                "/lnurlp/{username}/callback",
                web::get().to(lnurlp_callback),
            )
            .route(
                "/lnurlp/{username}/verify/{payment_hash}",
                web::get().to(lnurlp_verify),
            )
            // Admin routes
            .route("/admin", web::get().to(admin_interface))
            .route("/admin/login", web::post().to(admin_login))
            .route("/admin/users", web::get().to(admin_users))
            .route("/admin/add", web::post().to(admin_add_user))
            .route(
                "/admin/{username}/{domain}",
                web::delete().to(admin_delete_user),
            )
            .route(
                "/admin/{username}/{domain}/prism",
                web::put().to(admin_update_prism),
            )
            // Serve static files
            .service(fs::Files::new("/static", "static").show_files_listing())
    })
    .bind((bind_address.as_str(), port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::{MAX_ZAP_RECEIPT_RELAYS, extract_first_tag_value, extract_zap_receipt_relays};

    #[test]
    fn extract_zap_receipt_relays_dedupes_and_caps() {
        let zap_request = serde_json::json!({
            "tags": [[
                "relays",
                "wss://relay.one/",
                "wss://relay.one",
                "wss://relay.two",
                "wss://relay.three",
                "wss://relay.four",
                "wss://relay.five",
                "wss://relay.six"
            ]]
        });

        let relays = extract_zap_receipt_relays(&zap_request);

        assert_eq!(relays.len(), MAX_ZAP_RECEIPT_RELAYS);
        assert_eq!(relays[0], "wss://relay.one");
        assert_eq!(relays[1], "wss://relay.two");
        assert!(!relays.contains(&"wss://relay.six".to_string()));
    }

    #[test]
    fn extract_first_tag_value_reads_requested_tag() {
        let zap_request = serde_json::json!({
            "tags": [
                ["p", "pubkey-hex"],
                ["e", "event-id-hex"]
            ]
        });

        assert_eq!(
            extract_first_tag_value(&zap_request, "p").as_deref(),
            Some("pubkey-hex")
        );
        assert_eq!(
            extract_first_tag_value(&zap_request, "e").as_deref(),
            Some("event-id-hex")
        );
        assert_eq!(extract_first_tag_value(&zap_request, "a"), None);
    }
}
