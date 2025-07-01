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
    pub settled_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub nwc_uri: Option<String>,
    pub username: String,
    pub nostr_pubkey: Option<String>,
    pub domain: String,
    pub created_at: String,
}

pub async fn get_db_pool() -> SqlitePool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:rustress.db".to_string());
    
    if let Some(file_path) = database_url.strip_prefix("sqlite:") {
        if let Some(parent_dir) = std::path::Path::new(file_path).parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir)
                    .expect("Failed to create database directory");
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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username, domain)
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create users table");

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
            settled_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create invoices table");

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

    log::info!("Database setup completed successfully");
}

pub async fn create_user(
    pool: &SqlitePool,
    nwc_uri: Option<&str>,
    username: &str,
    nostr_pubkey: Option<&str>,
    domain: &str,
) -> Result<User, sqlx::Error> {
    let rec = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (nwc_uri, username, nostr_pubkey, domain)
        VALUES (?, ?, ?, ?)
        RETURNING id, nwc_uri, username, nostr_pubkey, domain, created_at
        "#,
    )
    .bind(nwc_uri)
    .bind(username)
    .bind(nostr_pubkey)
    .bind(domain)
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

pub async fn delete_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(r#"DELETE FROM users WHERE username = ?"#)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_all_users_with_secret(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"SELECT id, nwc_uri, username, nostr_pubkey, domain, created_at FROM users"#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_user_by_username_and_domain(pool: &SqlitePool, username: &str, domain: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"SELECT id, nwc_uri, username, nostr_pubkey, domain, created_at FROM users WHERE username = ? AND domain = ?"#,
    )
    .bind(username)
    .bind(domain)
    .fetch_one(pool)
    .await
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
        RETURNING id, user_id, amount, description, payment_request, payment_hash, preimage, metadata, settled_at, created_at
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
        r#"SELECT id, user_id, amount, description, payment_request, payment_hash, preimage, metadata, settled_at, created_at FROM invoices WHERE payment_hash = ?"#,
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
        for (k, v) in zap_json.as_object().unwrap_or(&serde_json::Map::new()) {
            obj.insert(k.clone(), v.clone());
        }
    }
    let new_metadata = serde_json::to_string(&meta_json).unwrap();
    sqlx::query(r#"UPDATE invoices SET metadata = ? WHERE payment_hash = ?"#)
        .bind(new_metadata)
        .bind(payment_hash)
        .execute(pool)
        .await?;
    Ok(())
}