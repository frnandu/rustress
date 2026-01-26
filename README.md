# rustress

A minimal LNurl/Nostr/Zap-receipt server in Rust using SQLite.

## Features
- LNURL-pay endpoint with NWC (Nostr Wallet Connect) integration
- NIP-05 endpoint for Nostr identity verification
- NIP-57 (zaps receipts publishing)
- **Prisms**: Automatic payment splitting to multiple lightning addresses
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
- `/admin/:username/:domain` (DELETE) - Delete user via admin interface
- `/admin/:username/:domain/prism` (PUT) - Update prism configuration

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
   - **Security Note**: Only use read-only connections with `make_invoice` permission only for regular users
5. **Prism Configuration** (optional): For automatic payment splitting
   - Enable prism mode to split received payments
   - Requires NWC with `pay_invoice` permission
   - Configure multiple splits with lightning addresses and percentages

## Prisms (Payment Splitting)

Prisms allow a lightning address to automatically split incoming payments to multiple recipients. When a payment is received by a prism-enabled address, it's automatically forwarded to the configured lightning addresses based on percentage splits.

### How Prisms Work

1. **Create a Prism User**: In the admin panel, check "Enable Prism" when adding a user
2. **Configure NWC**: Provide an NWC connection string with `pay_invoice` permission
3. **Add Splits**: Define one or more recipients with their lightning addresses and percentages
4. **Automatic Forwarding**: When the prism receives a payment, it automatically:
   - Receives the payment to the prism's NWC wallet
   - Calculates split amounts based on percentages
   - Pays out each split to the configured lightning addresses
   - Keeps any remaining percentage in the prism wallet

### Prism Configuration

- **Percentages**: Don't need to total 100% - remaining funds stay in the prism wallet
- **Minimum Split**: Each split must be at least 1 sat (1000 msats)
- **Recipients**: Use standard lightning addresses (user@domain.com)
- **NWC Permission**: Requires `pay_invoice` permission (unlike regular users)

### Example Use Cases

- **Revenue Sharing**: Split podcast payments among hosts
- **Automatic Donations**: Forward a percentage to charity
- **Team Payments**: Distribute earnings to team members
- **Savings**: Keep a percentage while forwarding the rest

### Security Considerations

⚠️ **Important**: Prisms require NWC with `pay_invoice` permission, which allows the server to send payments. Only use prisms with wallets you control and trust this server with.

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
- `PORT` - Server port (default: `8080`)
- `DATABASE_URL` - Database connection string (default: `sqlite:rustress.db`)
- `NIP57_PRIVATE_KEY` - Private key for signing zap receipts (required for NIP-57)

## Database
- Uses SQLite for storage
- Automatic migrations on startup
- Stores users, invoices, and payment metadata
