# rustress

A minimal Lightning/Nostr server in Rust using SQLite.

## Features
- LNURL-pay endpoint
- NIP-05 endpoint
- NIP-57 (zaps receipts publishing)
- API endpoint to add new entries

## Endpoints
- `/lnurlp/:username` - LNURL-pay
- `/.well-known/nostr.json` - NIP-05 verification
- `/api/add` (POST) - Add new entry
- `/zaps` - NIP-57 zaps receipts publishing

## Usage
- Build: `cargo build`
- Run: `cargo run`

## Database
- Uses SQLite for storage (see `migrations/` for schema) 