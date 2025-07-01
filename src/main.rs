use actix_web::web::Query;
use actix_web::{App, HttpResponse, HttpServer, Responder, web, cookie::Cookie, HttpRequest};
use actix_files as fs;
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
use tokio::time::{Duration, timeout};

mod db;

use crate::db::{
    create_user, delete_user_by_username, get_all_users_with_secret, get_db_pool,
    get_invoice_by_payment_hash, get_user_by_username_and_domain, insert_invoice, mark_invoice_settled,
    run_migrations, update_invoice_metadata_with_zap_receipt,
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
    if let Some(ref nostr_pubkey) = user.nostr_pubkey {
        if let Some(hex_pubkey) = npub_to_hex(nostr_pubkey).or_else(|| Some(nostr_pubkey.clone())) {
            resp["nostrPubkey"] = serde_json::json!(hex_pubkey);
            resp["allowsNostr"] = serde_json::json!(true);
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

async fn subscribe_nwc_notifications(pool: Arc<SqlitePool>) {
    let users = match get_all_users_with_secret(&pool).await {
        Ok(u) => u,
        Err(e) => {
            warn!("Failed to load users for NWC subscription: {}", e);
            return;
        }
    };
    for user in users {
        let pool = pool.clone();
        let secret = match &user.nwc_uri {
            Some(s) => s.clone(),
            None => {
                warn!("User {} has no NWC connection secret, skipping notifications", user.id);
                continue;
            }
        };
        let user_id = user.id;
        tokio::spawn(async move {
            // Create NWC client
            let uri = match NostrWalletConnectURI::from_str(&secret) {
                Ok(u) => u,
                Err(e) => {
                    warn!("Invalid NWC URI for user {}: {}", user_id, e);
                    return;
                }
            };
            let nwc = NWC::new(uri);
            if let Err(e) = nwc.subscribe_to_notifications().await {
                warn!(
                    "Failed to subscribe to notifications for user {}: {}",
                    user_id, e
                );
                return;
            }
            loop {
                let pool_cloned = pool.clone();
                let res = nwc
                    .handle_notifications(move |notification| {
                        let pool = pool_cloned.clone();
                        async move {
                            use nostr::nips::nip47::NotificationType;
                            if let NotificationType::PaymentReceived = notification.notification_type {
                                if let Ok(payment) = notification.to_pay_notification() {
                                    let payment_hash = payment.payment_hash.clone();
                                    let preimage = payment.preimage.clone();
                                    let user_id = user_id;
                                    tokio::spawn(async move {
                                        if let Err(e) = mark_invoice_settled(&pool, &payment_hash, &preimage).await {
                                            warn!("Failed to mark invoice settled for user {}: {}", user_id, e);
                                        }
                                        // 2. Fetch invoice metadata
                                        let invoice = match get_invoice_by_payment_hash(&pool, &payment_hash).await {
                                            Ok(inv) => inv,
                                            Err(e) => {
                                                warn!("Failed to get invoice by payment_hash: {}", e);
                                                return;
                                            }
                                        };
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
                                        let mut tags = vec![
                                            Tag::event(zap_request_event.id),
                                            Tag::from_standardized_without_cell(TagStandard::Bolt11(bolt11.clone())),
                                        ];
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
                    break;
                }
            }
        });
    }
}

async fn well_known_lnurlp(
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

    // Check if user exists
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
    if let Some(ref nostr_pubkey) = user.nostr_pubkey {
        if let Some(hex_pubkey) = npub_to_hex(nostr_pubkey).or_else(|| Some(nostr_pubkey.clone())) {
            resp["nostrPubkey"] = serde_json::json!(hex_pubkey);
            resp["allowsNostr"] = serde_json::json!(true);
        }
    }

    HttpResponse::Ok().json(resp)
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
            // Don't expose connection secrets in admin interface
            let safe_users: Vec<serde_json::Value> = users
                .into_iter()
                .map(|user| {
                    serde_json::json!({
                        "id": user.id,
                        "username": user.username,
                        "nostr_pubkey": user.nostr_pubkey,
                        "domain": user.domain,
                        "created_at": user.created_at
                    })
                })
                .collect();
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

    // Validate that at least one of the optional fields is provided and not empty
    let has_connection_secret = user_req.connection_secret.as_ref().map_or(false, |s| !s.trim().is_empty());
    let has_nostr_pubkey = user_req.nostr_pubkey.as_ref().map_or(false, |s| !s.trim().is_empty());
    
    if !has_connection_secret && !has_nostr_pubkey {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "ERROR", "reason": "At least one of 'connection_secret' (for LNURL) or 'nostr_pubkey' (for NIP-05) must be provided"}));
    }

    let username = user_req.username.clone().unwrap_or_else(|| {
        format!("{}", rand::random::<u64>())
    });

    match create_user(&pool, user_req.connection_secret.as_deref(), &username, user_req.nostr_pubkey.as_deref(), &user_req.domain).await {
        Ok(user) => {
            let lightning_address = format!("{}@{}", user.username, user.domain);
            HttpResponse::Ok().json(serde_json::json!({"lightning_address": lightning_address}))
        }
        Err(e) => HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "ERROR", "reason": e.to_string()})),
    }
}

async fn admin_delete_user(
    req: HttpRequest,
    pool: web::Data<Arc<SqlitePool>>,
    config: web::Data<Arc<AppConfig>>,
    path: web::Path<String>,
) -> impl Responder {
    if !check_admin_auth(&req, &config.admin_password) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"status": "ERROR", "reason": "Authentication required"}));
    }

    let username = path.into_inner();
    match delete_user_by_username(&pool, &username).await {
        Ok(deleted) => {
            if deleted {
                HttpResponse::Ok().json(serde_json::json!({
                    "status": "OK",
                    "message": format!("User '{}' deleted successfully", username)
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "status": "ERROR",
                    "reason": format!("User '{}' not found", username)
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "ERROR",
            "reason": e.to_string()
        })),
    }
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

    // Generate admin password and print to stdout
    let admin_password = generate_admin_password();
    println!("🔐 ADMIN PASSWORD: {}", admin_password);
    println!("💡 Save this password - it's required to access /admin");

    let config = Arc::new(AppConfig {
        admin_password,
    });

    let bind_address = std_env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    info!("Starting server at {}:8080", bind_address);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config.clone()))
            .route("/lnurlp/{username}", web::get().to(lnurlp))
            .route(
                "/.well-known/lnurlp/{username}",
                web::get().to(well_known_lnurlp),
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
            .route("/admin/{username}", web::delete().to(admin_delete_user))
            // Serve static files
            .service(fs::Files::new("/static", "static").show_files_listing())
    })
    .bind((bind_address.as_str(), 8080))?
    .run()
    .await
}
