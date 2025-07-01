# rustress

A minimal Lightning/Nostr server in Rust using SQLite.

## Features
- LNURL-pay endpoint with NWC (Nostr Wallet Connect) integration
- NIP-05 endpoint for Nostr identity verification
- NIP-57 (zaps receipts publishing)
- Web-based admin dashboard for user management
- Multi-domain support
- Secure authentication system

## Endpoints

### Public Endpoints
- `/lnurlp/:username` - LNURL-pay endpoint
- `/.well-known/lnurlp/:username` - Well-known LNURL-pay endpoint
- `/.well-known/nostr.json` - NIP-05 verification
- `/lnurlp/:username/callback` - LNURL-pay callback
- `/lnurlp/:username/verify/:payment_hash` - Payment verification

### Admin Dashboard
- `/admin` - Admin interface (requires authentication)
- `/admin/login` (POST) - Admin authentication
- `/admin/users` (GET) - List all users
- `/admin/add` (POST) - Add user via admin interface
- `/admin/:username` (DELETE) - Delete user via admin interface

## Admin Dashboard Features

The admin dashboard provides a web-based interface for managing users and Lightning addresses.

### Authentication
- Secure password-based authentication using randomly generated admin passwords
- Admin password is generated on server startup and printed to console/logs
- Session-based authentication with HTTP-only cookies
- 24-hour session timeout

### User Management
- **Add Users**: Create new users with Lightning addresses
- **View Users**: List all registered users with their details
- **Delete Users**: Remove users from the system
- **Multi-domain Support**: Each user can have different domains

### User Configuration Options
When adding users, you can configure:

1. **Username** (optional): Custom username or auto-generated if not provided
2. **Domain** (required): The domain for the Lightning address (e.g., `example.com`)
3. **Nostr Public Key** (optional): For NIP-05 verification support
   - Accepts both npub format (`npub1...`) and hex format
   - Enables Nostr identity verification at `username@domain`
4. **NWC Connection String** (optional): For LNURL-pay functionality
   - Nostr Wallet Connect URI (`nostr+walletconnect://...`)
   - Enables Lightning payments to `username@domain`
   - **Security Note**: Only use read-only connections with `make_invoice` permission only

### Security Features
- Admin password displayed only on server startup
- NWC connection strings stored securely (for invoice generation only)
- Session-based authentication with automatic expiration
- Input validation for all user data
- CSRF protection through session cookies

### Requirements
At least one of the following must be provided when creating a user:
- **Nostr Public Key**: Enables NIP-05 verification
- **NWC Connection String**: Enables LNURL-pay functionality

Both can be provided to enable full Lightning + Nostr functionality.

## Usage

### Starting the Server
```bash
# Build the project
cargo build

# Run the server
cargo run
```

### Accessing Admin Dashboard
1. Start the server and note the admin password printed to console
2. Navigate to `http://localhost:8080/admin`
3. Enter the admin password to access the dashboard
4. Use the interface to manage users and Lightning addresses

### Environment Variables
- `BIND_ADDRESS` - Server bind address (default: `127.0.0.1`)
- `NIP57_PRIVATE_KEY` - Private key for signing zap receipts (required for NIP-57)

## Database
- Uses SQLite for storage
- Automatic migrations on startup
- Stores users, invoices, and payment metadata
