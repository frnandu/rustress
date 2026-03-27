use actix_web::web::Query;
use actix_web::{App, HttpResponse, HttpServer, Responder, web, cookie::Cookie, HttpRequest};
use actix_files as fs;
use actix_cors::Cors;
use log::{info, warn};
use nostr::prelude::*;
use nostr_sdk::{
    Client, Event as SdkEvent, EventBuilder as SdkEventBuilder, Keys as SdkKeys, Kind,
    SecretKey as SdkSecretKey, Tag, TagStandard,
};
use nwc::prelude::*;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::env as std_env;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{Duration, sleep, timeout};

mod db;

use crate::db::{
    create_user, delete_user_by_username_and_domain, get_all_users_with_secret, get_db_pool,
    get_invoice_by_payment_hash, get_user_by_username_and_domain, insert_invoice, mark_invoice_settled,
    run_migrations, update_invoice_metadata_with_zap_receipt, add_prism_split, get_prism_splits_by_user_id,
    delete_prism_splits_by_user_id, update_user_prism_status, update_user_details,
};

#[derive(Clone)]
struct AppConfig {
    admin_password: String,
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

async fn lnurlp(
    pool: web::Data<Arc<SqlitePool>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let username = path.into_inner();
    
    // Extract domain from Host header
    let host = req.headers().get("host")
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
    
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };
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
        let host = req.headers().get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost:8080");
        // Remove port from host if present
        let domain = host.split(':').next().unwrap_or(host);

        let user_result = get_user_by_username_and_domain(&pool, username, domain).await;
        match user_result {
            Ok(user) => {
                let hex_pubkey = user.nostr_pubkey.as_ref().and_then(|npub| npub_to_hex(npub));
                HttpResponse::Ok().json(serde_json::json!({
                    "names": { user.username: hex_pubkey }
                }))
            },
            Err(_) => {
                HttpResponse::Ok().json(serde_json::json!({"names": {}}))
            },
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
    let host = req.headers().get("host")
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
    let uri = match NostrWalletConnectURI::from_str(nwc_secret) {
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
    let host = req.headers().get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };
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
    log::info!("Starting prism payment processing for user {} with amount {} msats", user_id, amount_msats);
    
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
            log::warn!("Split amount too small ({} msats) for {}, skipping", split_amount_msats, split.lightning_address);
            continue;
        }
        
        log::info!("Processing prism split: {}% ({} msats) to {}", split.percentage, split_amount_msats, split.lightning_address);
        
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
                        log::info!("Got LNURL response from {}, status: {}", lnurl_url, response.status());
                        match timeout(Duration::from_secs(5), response.json::<serde_json::Value>()).await {
                            Ok(Ok(lnurl_response)) => {
                                log::info!("Parsed LNURL response: {:?}", lnurl_response);
                                if let Some(callback) = lnurl_response.get("callback").and_then(|c| c.as_str()) {
                                    // Request invoice from callback
                                    let invoice_url = format!("{}?amount={}", callback, split_amount_msats);
                                    log::info!("Requesting invoice from callback: {}", invoice_url);
                                    
                                    match timeout(Duration::from_secs(10), client.get(&invoice_url).send()).await {
                                        Ok(Ok(inv_response)) => {
                                            log::info!("Got invoice response, status: {}", inv_response.status());
                                            match timeout(Duration::from_secs(5), inv_response.json::<serde_json::Value>()).await {
                                                Ok(Ok(inv_json)) => {
                                                    log::info!("Parsed invoice response: {:?}", inv_json);
                                                    if let Some(pr) = inv_json.get("pr").and_then(|p| p.as_str()) {
                                                        log::info!("Got payment request: {}", if pr.len() > 50 { &pr[..50] } else { pr });
                                                        // Pay the invoice using NWC
                                                        let pay_request = PayInvoiceRequest {
                                                            id: None,
                                                            invoice: pr.to_string(),
                                                            amount: None,
                                                        };
                                                        log::info!("Paying invoice via NWC...");
                                                        match timeout(Duration::from_secs(30), nwc.pay_invoice(pay_request)).await {
                                                            Ok(Ok(response)) => {
                                                                log::info!("Successfully paid {} msats to {}, preimage: {:?}", split_amount_msats, split.lightning_address, response.preimage);
                                                            }
                                                            Ok(Err(e)) => {
                                                                log::error!("Failed to pay invoice to {}: {}", split.lightning_address, e);
                                                            }
                                                            Err(_) => {
                                                                log::error!("Timeout paying invoice to {}", split.lightning_address);
                                                            }
                                                        }
                                                    } else {
                                                        log::error!("No 'pr' field in invoice response");
                                                    }
                                                }
                                                Ok(Err(e)) => {
                                                    log::error!("Failed to parse invoice JSON: {}", e);
                                                }
                                                Err(_) => {
                                                    log::error!("Timeout parsing invoice JSON response");
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            log::error!("Failed to get invoice from {}: {}", invoice_url, e);
                                        }
                                        Err(_) => {
                                            log::error!("Timeout getting invoice from {}", invoice_url);
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
                        log::error!("Failed to resolve lightning address {}: {}", split.lightning_address, e);
                    }
                    Err(_) => {
                        log::error!("Timeout resolving lightning address {}", split.lightning_address);
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn spawn_nwc_notification_listener(pool: Arc<SqlitePool>, user_id: i64, secret: String) {
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
            let res = nwc
                .handle_notifications(move |notification| {
                        let pool = pool_cloned.clone();
                        let nwc_secret = secret_cloned.clone();
                        async move {
                            use nostr::nips::nip47::NotificationType;
                            if let NotificationType::PaymentReceived = notification.notification_type {
                                if let Ok(payment) = notification.to_pay_notification() {
                                    let payment_hash = payment.payment_hash.clone();
                                    let preimage = payment.preimage.clone();
                                    let user_id_clone = user_id;
                                    let pool_clone = pool.clone();
                                    let nwc_secret_clone = nwc_secret.as_ref().clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = mark_invoice_settled(&pool_clone, &payment_hash, &preimage).await {
                                            warn!("Failed to mark invoice settled for user {}: {}", user_id_clone, e);
                                        }
                                        // 2. Fetch invoice metadata
                                        let invoice = match get_invoice_by_payment_hash(&pool_clone, &payment_hash).await {
                                            Ok(inv) => inv,
                                            Err(e) => {
                                                warn!("Failed to get invoice by payment_hash: {}", e);
                                                return;
                                            }
                                        };
                                        
                                        // Get the invoice recipient's user details to check if THEY are a prism
                                        // (not the NWC owner who might be different)
                                        let invoice_user_id = invoice.user_id;
                                        log::info!("Payment notification from NWC owner (user {}), but invoice belongs to user {}", user_id_clone, invoice_user_id);
                                        
                                        // Fetch the invoice user's details to check if they're a prism
                                        let invoice_user = match sqlx::query_as::<_, crate::db::User>(
                                            r#"SELECT id, nwc_uri, username, nostr_pubkey, domain, is_prism, created_at FROM users WHERE id = ?"#
                                        )
                                        .bind(invoice_user_id)
                                        .fetch_one(pool_clone.as_ref())
                                        .await {
                                            Ok(u) => u,
                                            Err(e) => {
                                                warn!("Failed to fetch invoice user {}: {}", invoice_user_id, e);
                                                return;
                                            }
                                        };
                                        
                                        // Process prism payment splits if the INVOICE USER is a prism
                                        log::info!("Checking prism status: is_prism={} for invoice user {}", invoice_user.is_prism, invoice_user_id);
                                        if invoice_user.is_prism {
                                            let amount_msats = invoice.amount as u64;
                                            log::info!("Invoice user {} is a prism, processing payment split for {} msats", invoice_user_id, amount_msats);
                                            // Use the NWC secret from the NWC owner (user_id_clone) to make payments
                                            if let Err(e) = process_prism_payment(&pool_clone, invoice_user_id, amount_msats, &nwc_secret_clone).await {
                                                warn!("Failed to process prism payment for user {}: {}", invoice_user_id, e);
                                            } else {
                                                log::info!("Successfully completed prism payment processing for user {}", invoice_user_id);
                                            }
                                        }
                                        
                                        let metadata = invoice.metadata.as_deref().unwrap_or("");
                                        let meta_json: serde_json::Value = match serde_json::from_str(metadata) {
                                            Ok(j) => j,
                                            Err(_) => return,
                                        };
                                        let zap_request = match meta_json.get("nostr") {
                                            Some(z) => z,
                                            None => return,
                                        };
                                        // 3. Parse zap request and relays
                                        let relays = zap_request
                                            .get("tags")
                                            .and_then(|tags| tags.as_array())
                                            .and_then(|tags| {
                                                tags.iter().find(|t| {
                                                    t.get(0) == Some(&serde_json::json!("relays"))
                                                })
                                            })
                                            .and_then(|relays_tag| relays_tag.as_array())
                                            .map(|arr| {
                                                arr.iter()
                                                    .skip(1)
                                                    .filter_map(|v| v.as_str())
                                                    .collect::<Vec<_>>()
                                            })
                                            .unwrap_or_default();
                                        if relays.is_empty() {
                                            return;
                                        }
                                        // 4. Build and sign zap receipt event
                                        let sk = std::env::var("NIP57_PRIVATE_KEY").expect("NIP57_PRIVATE_KEY not set");
                                        let sk = SdkSecretKey::from_str(&sk).expect("Invalid NIP57_PRIVATE_KEY");
                                        let sdk_keys = SdkKeys::new(sk.clone());
                                        let zap_request_event: SdkEvent = match serde_json::from_value(zap_request.clone()) {
                                            Ok(ev) => ev,
                                            Err(e) => {
                                                warn!("Failed to parse zap request event: {}", e);
                                                return;
                                            }
                                        };
                                        let bolt11 = invoice.payment_request.clone();
                                        let preimage_opt = invoice.preimage.clone();
                                        // Extract the 'e' tag from the zap request (the event being zapped)
                                        let zapped_event_id = zap_request
                                            .get("tags")
                                            .and_then(|tags| tags.as_array())
                                            .and_then(|tags| {
                                                tags.iter().find(|t| {
                                                    t.get(0) == Some(&serde_json::json!("e"))
                                                })
                                            })
                                            .and_then(|e_tag| e_tag.as_array())
                                            .and_then(|e_tag| e_tag.get(1))
                                            .and_then(|id_str| id_str.as_str())
                                            .and_then(|id_str| nostr::EventId::from_str(id_str).ok());
                                        
                                        let mut tags = vec![
                                            Tag::from_standardized_without_cell(TagStandard::Bolt11(bolt11.clone())),
                                        ];
                                        
                                        // Add the 'e' tag with the event being zapped
                                        if let Some(event_id) = zapped_event_id {
                                            // Convert from nostr::EventId to nostr_sdk::EventId
                                            let sdk_event_id = nostr_sdk::EventId::from_hex(&event_id.to_hex()).unwrap();
                                            tags.push(Tag::event(sdk_event_id));
                                        }
                                        
                                        // Add the 'p' tag with the pubkey of the person being zapped
                                        tags.push(Tag::public_key(zap_request_event.pubkey));
                                        
                                        // Add the 'P' tag with the pubkey of the zap request sender
                                        tags.push(Tag::parse(vec!["P".to_string(), zap_request_event.pubkey.to_string()]).unwrap());
                                        
                                        // Add the 'description' tag with the JSON-encoded zap request
                                        tags.push(Tag::parse(vec!["description".to_string(), serde_json::to_string(&zap_request).unwrap()]).unwrap());
                                        
                                        if let Some(preimage) = &preimage_opt {
                                            tags.push(Tag::from_standardized_without_cell(TagStandard::Preimage(preimage.clone())));
                                        }
                                        let zap_receipt_event = match SdkEventBuilder::new(Kind::ZapReceipt, "")
                                            .tags(tags)
                                            .sign_with_keys(&sdk_keys) {
                                            Ok(ev) => ev,
                                            Err(e) => {
                                                warn!("Failed to sign zap receipt event: {}", e);
                                                return;
                                            }
                                        };
                                        
                                        // Log the signed zap receipt event in debug level
                                        let zap_receipt_json = serde_json::to_string(&zap_receipt_event).unwrap_or_default();
                                        log::debug!("Signed zap receipt event: {}", zap_receipt_json);
                                        // 5. Publish to relays
                                        let client = Client::new(sdk_keys);
                                        for relay_url in &relays {
                                            let _ = client.add_relay(*relay_url).await;
                                        }
                                        let _ = client.connect().await;
                                        let publish_result = timeout(Duration::from_secs(10), client.send_event(&zap_receipt_event)).await;
                                        match publish_result {
                                            Ok(Ok(_)) => {
                                                info!("Published zap receipt event {} to relays: {:?}", zap_receipt_event.id, relays);
                                            }
                                            Ok(Err(e)) => {
                                                warn!("Failed to publish zap receipt event: {}", e);
                                            }
                                            Err(_) => {
                                                warn!("Timeout publishing zap receipt event");
                                            }
                                        }
                                        // 6. Update invoice metadata with zap_receipt event JSON
                                        let zap_receipt_json = serde_json::to_string(&zap_receipt_event).unwrap_or_default();
                                        if let Err(e) = update_invoice_metadata_with_zap_receipt(&pool, &payment_hash, &zap_receipt_json).await {
                                            warn!("Failed to update invoice metadata with zap receipt for user {}: {}", user_id, e);
                                        }
                                    });
                                }
                            }
                            Ok::<bool, Box<dyn std::error::Error>>(false)
                        }
                    })
                    .await;

            if let Err(e) = res {
                warn!(
                    "Error handling NWC notification for user {}: {}",
                    user_id, e
                );
            } else {
                warn!(
                    "NWC notification stream ended for user {}, reconnecting",
                    user_id
                );
            }

            sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn subscribe_nwc_notifications(pool: Arc<SqlitePool>) {
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
                warn!("User {} has no NWC connection secret, skipping notifications", user.id);
                continue;
            }
        };

        spawn_nwc_notification_listener(pool.clone(), user.id, secret);
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
        return HttpResponse::Unauthorized()
            .body(include_str!("../static/login.html"));
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
        let has_connection_secret = user_req.connection_secret.as_ref().map_or(false, |s| !s.trim().is_empty());
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
        let has_connection_secret = user_req.connection_secret.as_ref().map_or(false, |s| !s.trim().is_empty());
        let has_nostr_pubkey = user_req.nostr_pubkey.as_ref().map_or(false, |s| !s.trim().is_empty());
        
        if !has_connection_secret && !has_nostr_pubkey {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "ERROR", "reason": "At least one of 'connection_secret' (for LNURL) or 'nostr_pubkey' (for NIP-05) must be provided"}));
        }
    }

    let username = user_req.username.clone().unwrap_or_else(|| {
        format!("{}", rand::random::<u64>())
    });

    match create_user(&pool, user_req.connection_secret.as_deref(), &username, user_req.nostr_pubkey.as_deref(), &user_req.domain, is_prism).await {
        Ok(user) => {
            // If prism, add splits
            if is_prism {
                if let Some(splits) = &user_req.prism_splits {
                    for split in splits {
                        if let Err(e) = add_prism_split(&pool, user.id, &split.lightning_address, split.percentage).await {
                            // Rollback by deleting user
                            let _ = delete_user_by_username_and_domain(&pool, &user.username, &user.domain).await;
                            return HttpResponse::InternalServerError()
                                .json(serde_json::json!({"status": "ERROR", "reason": format!("Failed to add prism split: {}", e)}));
                        }
                    }
                }
            }

            if let Some(secret) = user_req.connection_secret.clone() {
                if !secret.trim().is_empty() {
                    spawn_nwc_notification_listener(pool.get_ref().clone(), user.id, secret);
                }
            }
            
            let lightning_address = format!("{}@{}", user.username, user.domain);
            HttpResponse::Ok().json(serde_json::json!({"lightning_address": lightning_address, "is_prism": is_prism}))
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
        Err(_) => return HttpResponse::NotFound()
            .json(serde_json::json!({"status": "ERROR", "reason": "User not found"})),
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
        let nostr_to_update = user_req.nostr_pubkey.as_deref().or(user.nostr_pubkey.as_deref());
        
        if let Err(e) = update_user_details(&pool, user.id, nwc_to_update, nostr_to_update).await {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()}));
        }

        if let Some(new_secret) = &user_req.nwc_uri {
            if !new_secret.trim().is_empty() && user.nwc_uri.as_deref() != Some(new_secret.as_str()) {
                spawn_nwc_notification_listener(pool.get_ref().clone(), user.id, new_secret.clone());
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
                if let Err(e) = add_prism_split(&pool, user.id, &split.lightning_address, split.percentage).await {
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

    // Start NWC subscription after database is ready
    let pool_for_nwc = pool.clone();
    tokio::spawn(async move {
        subscribe_nwc_notifications(pool_for_nwc).await;
    });

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

    let config = Arc::new(AppConfig {
        admin_password,
    });

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
            .route("/lnurlp/{username}", web::get().to(lnurlp))
            .route(
                "/.well-known/lnurlp/{username}",
                web::get().to(lnurlp),
            )
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
            .route("/admin/{username}/{domain}", web::delete().to(admin_delete_user))
            .route("/admin/{username}/{domain}/prism", web::put().to(admin_update_prism))
            // Serve static files
            .service(fs::Files::new("/static", "static").show_files_listing())
    })
    .bind((bind_address.as_str(), port))?
    .run()
    .await
}
