use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Invoice {
    pub id: i64,
    pub user_id: i64,
    pub amount: i64,
    pub description: Option<String>,
    pub payment_request: String,
    pub payment_hash: String,
    pub preimage: Option<String>,
    pub metadata: Option<String>,
    pub zap_receipt_json: Option<String>,
    pub zap_receipt_status: Option<String>,
    pub zap_receipt_attempts: i64,
    pub zap_receipt_last_error: Option<String>,
    pub zap_receipt_last_attempt_at: Option<String>,
    pub zap_receipt_published_at: Option<String>,
    pub zap_receipt_success_relays: Option<String>,
    pub zap_receipt_failed_relays: Option<String>,
    pub settled_at: Option<String>,
    pub created_at: String,
}

pub const ZAP_RECEIPT_STATUS_PENDING: &str = "pending";
pub const ZAP_RECEIPT_STATUS_PUBLISHED: &str = "published";
pub const ZAP_RECEIPT_STATUS_FAILED: &str = "failed";

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub nwc_uri: Option<String>,
    pub username: String,
    pub nostr_pubkey: Option<String>,
    pub domain: String,
    pub is_prism: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
pub struct PrismSplit {
    pub id: i64,
    pub user_id: i64,
    pub lightning_address: String,
    pub percentage: f64,
    pub created_at: String,
}

pub async fn get_db_pool() -> SqlitePool {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:rustress.db".to_string());

    if let Some(file_path) = database_url.strip_prefix("sqlite:") {
        if let Some(parent_dir) = std::path::Path::new(file_path).parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir).expect("Failed to create database directory");
            }
        }
    }

    let options = sqlx::sqlite::SqliteConnectOptions::from_str(&database_url)
        .expect("Invalid database URL")
        .create_if_missing(true);

    SqlitePool::connect_with(options)
        .await
        .expect("Failed to connect to DB")
}

pub async fn run_migrations(pool: &SqlitePool) {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nwc_uri TEXT,
            username TEXT NOT NULL,
            nostr_pubkey TEXT,
            domain TEXT NOT NULL,
            is_prism BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username, domain)
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create users table");

    // Add is_prism column to existing users table if it doesn't exist
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_prism BOOLEAN NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            description TEXT,
            payment_request TEXT NOT NULL,
            payment_hash TEXT NOT NULL UNIQUE,
            preimage TEXT,
            metadata TEXT,
            zap_receipt_json TEXT,
            zap_receipt_status TEXT,
            zap_receipt_attempts INTEGER NOT NULL DEFAULT 0,
            zap_receipt_last_error TEXT,
            zap_receipt_last_attempt_at DATETIME,
            zap_receipt_published_at DATETIME,
            zap_receipt_success_relays TEXT,
            zap_receipt_failed_relays TEXT,
            settled_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create invoices table");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS prism_splits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            lightning_address TEXT NOT NULL,
            percentage REAL NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create prism_splits table");

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        .execute(pool)
        .await
        .expect("Failed to create users username index");

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_invoices_payment_hash ON invoices(payment_hash)")
        .execute(pool)
        .await
        .expect("Failed to create invoices payment_hash index");

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id)")
        .execute(pool)
        .await
        .expect("Failed to create invoices user_id index");

    let invoice_alters = [
        "ALTER TABLE invoices ADD COLUMN zap_receipt_json TEXT",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_status TEXT",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_last_error TEXT",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_last_attempt_at DATETIME",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_published_at DATETIME",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_success_relays TEXT",
        "ALTER TABLE invoices ADD COLUMN zap_receipt_failed_relays TEXT",
    ];
    for statement in invoice_alters {
        let _ = sqlx::query(statement).execute(pool).await;
    }

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_invoices_zap_receipt_status ON invoices(zap_receipt_status)")
        .execute(pool)
        .await
        .expect("Failed to create invoices zap receipt status index");

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_prism_splits_user_id ON prism_splits(user_id)")
        .execute(pool)
        .await
        .expect("Failed to create prism_splits user_id index");

    log::info!("Database setup completed successfully");
}

pub async fn create_user(
    pool: &SqlitePool,
    nwc_uri: Option<&str>,
    username: &str,
    nostr_pubkey: Option<&str>,
    domain: &str,
    is_prism: bool,
) -> Result<User, sqlx::Error> {
    let rec = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (nwc_uri, username, nostr_pubkey, domain, is_prism)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id, nwc_uri, username, nostr_pubkey, domain, is_prism, created_at
        "#,
    )
    .bind(nwc_uri)
    .bind(username)
    .bind(nostr_pubkey)
    .bind(domain)
    .bind(is_prism)
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

pub async fn delete_user_by_username_and_domain(
    pool: &SqlitePool,
    username: &str,
    domain: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(r#"DELETE FROM users WHERE username = ? AND domain = ?"#)
        .bind(username)
        .bind(domain)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_all_users_with_secret(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"SELECT id, nwc_uri, username, nostr_pubkey, domain, is_prism, created_at FROM users"#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_user_by_username_and_domain(
    pool: &SqlitePool,
    username: &str,
    domain: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"SELECT id, nwc_uri, username, nostr_pubkey, domain, is_prism, created_at FROM users WHERE username = ? AND domain = ?"#,
    )
    .bind(username)
    .bind(domain)
    .fetch_one(pool)
    .await
}

// Prism-related functions
pub async fn add_prism_split(
    pool: &SqlitePool,
    user_id: i64,
    lightning_address: &str,
    percentage: f64,
) -> Result<PrismSplit, sqlx::Error> {
    let rec = sqlx::query_as::<_, PrismSplit>(
        r#"
        INSERT INTO prism_splits (user_id, lightning_address, percentage)
        VALUES (?, ?, ?)
        RETURNING id, user_id, lightning_address, percentage, created_at
        "#,
    )
    .bind(user_id)
    .bind(lightning_address)
    .bind(percentage)
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

pub async fn get_prism_splits_by_user_id(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<PrismSplit>, sqlx::Error> {
    sqlx::query_as::<_, PrismSplit>(
        r#"SELECT id, user_id, lightning_address, percentage, created_at FROM prism_splits WHERE user_id = ?"#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn delete_prism_splits_by_user_id(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(r#"DELETE FROM prism_splits WHERE user_id = ?"#)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_user_prism_status(
    pool: &SqlitePool,
    user_id: i64,
    is_prism: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(r#"UPDATE users SET is_prism = ? WHERE id = ?"#)
        .bind(is_prism)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_user_details(
    pool: &SqlitePool,
    user_id: i64,
    nwc_uri: Option<&str>,
    nostr_pubkey: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(r#"UPDATE users SET nwc_uri = ?, nostr_pubkey = ? WHERE id = ?"#)
        .bind(nwc_uri)
        .bind(nostr_pubkey)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_invoice(
    pool: &SqlitePool,
    user_id: i64,
    amount: i64,
    description: &str,
    payment_request: &str,
    payment_hash: &str,
    metadata: &str,
) -> Result<Invoice, sqlx::Error> {
    let rec = sqlx::query_as::<_, Invoice>(
        r#"
        INSERT INTO invoices (user_id, amount, description, payment_request, payment_hash, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id, user_id, amount, description, payment_request, payment_hash, preimage, metadata,
                  zap_receipt_json, zap_receipt_status, zap_receipt_attempts, zap_receipt_last_error,
                  zap_receipt_last_attempt_at, zap_receipt_published_at, zap_receipt_success_relays,
                  zap_receipt_failed_relays, settled_at, created_at
        "#,
    )
    .bind(user_id)
    .bind(amount)
    .bind(description)
    .bind(payment_request)
    .bind(payment_hash)
    .bind(metadata)
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

pub async fn mark_invoice_settled(
    pool: &SqlitePool,
    payment_hash: &str,
    preimage: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"UPDATE invoices SET preimage = ?, settled_at = CURRENT_TIMESTAMP WHERE payment_hash = ?"#,
    )
    .bind(preimage)
    .bind(payment_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_invoice_by_payment_hash(
    pool: &SqlitePool,
    payment_hash: &str,
) -> Result<Invoice, sqlx::Error> {
    sqlx::query_as::<_, Invoice>(
        r#"SELECT id, user_id, amount, description, payment_request, payment_hash, preimage, metadata,
                  zap_receipt_json, zap_receipt_status, zap_receipt_attempts, zap_receipt_last_error,
                  zap_receipt_last_attempt_at, zap_receipt_published_at, zap_receipt_success_relays,
                  zap_receipt_failed_relays, settled_at, created_at
           FROM invoices
           WHERE payment_hash = ?"#,
    )
    .bind(payment_hash)
    .fetch_one(pool)
    .await
}

pub async fn update_invoice_metadata_with_zap_receipt(
    pool: &SqlitePool,
    payment_hash: &str,
    zap_receipt_json: &str,
) -> Result<(), sqlx::Error> {
    let invoice = get_invoice_by_payment_hash(pool, payment_hash).await?;
    let mut meta_json: serde_json::Value = match invoice.metadata {
        Some(ref s) => serde_json::from_str(s).unwrap_or(serde_json::json!({})),
        None => serde_json::json!({}),
    };
    let zap_json: serde_json::Value =
        serde_json::from_str(zap_receipt_json).unwrap_or(serde_json::json!({}));
    if let Some(obj) = meta_json.as_object_mut() {
        obj.insert("zap_receipt".to_string(), zap_json);
    }
    let new_metadata = serde_json::to_string(&meta_json).unwrap();
    sqlx::query(r#"UPDATE invoices SET metadata = ? WHERE payment_hash = ?"#)
        .bind(new_metadata)
        .bind(payment_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_invoice_zap_receipt_state(
    pool: &SqlitePool,
    payment_hash: &str,
    zap_receipt_json: &str,
    status: &str,
    success_relays_json: Option<&str>,
    failed_relays_json: Option<&str>,
    last_error: Option<&str>,
    published: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE invoices
        SET zap_receipt_json = ?,
            zap_receipt_status = ?,
            zap_receipt_attempts = COALESCE(zap_receipt_attempts, 0) + 1,
            zap_receipt_last_error = ?,
            zap_receipt_last_attempt_at = CURRENT_TIMESTAMP,
            zap_receipt_published_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE zap_receipt_published_at END,
            zap_receipt_success_relays = ?,
            zap_receipt_failed_relays = ?
        WHERE payment_hash = ?
        "#,
    )
    .bind(zap_receipt_json)
    .bind(status)
    .bind(last_error)
    .bind(published)
    .bind(success_relays_json)
    .bind(failed_relays_json)
    .bind(payment_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_pending_zap_receipt_invoices(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<Invoice>, sqlx::Error> {
    sqlx::query_as::<_, Invoice>(
        r#"
        SELECT id, user_id, amount, description, payment_request, payment_hash, preimage, metadata,
               zap_receipt_json, zap_receipt_status, zap_receipt_attempts, zap_receipt_last_error,
               zap_receipt_last_attempt_at, zap_receipt_published_at, zap_receipt_success_relays,
               zap_receipt_failed_relays, settled_at, created_at
        FROM invoices
        WHERE settled_at IS NOT NULL
          AND metadata IS NOT NULL
          AND json_extract(metadata, '$.nostr') IS NOT NULL
          AND zap_receipt_published_at IS NULL
        ORDER BY
          CASE COALESCE(zap_receipt_status, '') WHEN 'failed' THEN 0 ELSE 1 END,
          COALESCE(zap_receipt_last_attempt_at, settled_at, created_at) ASC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}
