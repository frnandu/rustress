# Docker Usage

## GitHub Container Registry

This project automatically builds and publishes Docker images to GitHub Container Registry (ghcr.io) via GitHub Actions.

### Available Images

- `ghcr.io/[username]/rustress:latest` - Latest build from main/master branch
- `ghcr.io/[username]/rustress:v*` - Tagged releases (e.g., v1.0.0)

### Running the Published Image

```bash
# Pull and run the latest image (database will be created in container)
docker run -p 8080:8080 ghcr.io/[username]/rustress:latest

# Run with persistent database storage
docker run -p 8080:8080 \
  -e DATABASE_URL=sqlite:rustress.db \
  -e RUST_LOG=info \
  -e BIND_ADDRESS=0.0.0.0 \
  ghcr.io/[username]/rustress:latest

# Run with environment file and persistent storage
docker run -p 8080:8080 \
  --env-file .env \
  ghcr.io/[username]/rustress:latest

# Run locally built image with persistent database
docker run --name rustress --rm -p 8080:8080 \
  --env-file .env \
  rustress
```

### Building Locally

```bash
# Build the image
docker build -t rustress .

# Run the local image
docker run -p 8080:8080 rustress
```

### Environment Variables

- `DATABASE_URL` - SQLite database path (default: `sqlite:rustress.db`)
- `RUST_LOG` - Log level (default: `info`)
- `BIND_ADDRESS` - Server bind address (default: `0.0.0.0`)
- `BASE_URL` - Base URL for callbacks (default: `https://example.com`)
- `DOMAIN` - Domain for lightning addresses (default: `example.com`)
- `NIP57_PRIVATE_KEY` - Private key for signing zap receipts (optional)
- `NOSTR_NIP57_PRIVATE_KEY` - Alternative name for NIP57 private key (optional)

### Database Initialization

The application automatically creates the required database schema on startup:
- Creates `users` and `invoices` tables if they don't exist
- Sets up necessary indexes for optimal performance
- No manual database setup required

### Notes

- The workflow builds multi-arch images (amd64 and arm64)
- Images are automatically tagged with branch names and semantic versions
- Pull requests build images but don't publish them
- The `latest` tag is only updated on the default branch
- Database schema is automatically initialized on first startup
