# Docker Usage

## GitHub Container Registry

This project automatically builds and publishes Docker images to GitHub Container Registry (ghcr.io) via GitHub Actions.

### Available Images

- `ghcr.io/[username]/rustress:latest` - Latest build from main/master branch
- `ghcr.io/[username]/rustress:v*` - Tagged releases (e.g., v1.0.0)

### Running the Published Image

```bash
# Pull and run the latest image
docker run -p 8080:8080 ghcr.io/[username]/rustress:latest

# Run with environment variables
docker run -p 8080:8080 \
  -e DATABASE_URL=sqlite:/app/data/rustress.db \
  -e RUST_LOG=info \
  -e BIND_ADDRESS=0.0.0.0 \
  -v $(pwd)/data:/app/data \
  ghcr.io/[username]/rustress:latest

# Run with custom configuration
docker run -p 8080:8080 \
  --env-file .env \
  -v $(pwd)/data:/app/data \
  ghcr.io/[username]/rustress:latest
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

### Notes

- The workflow builds multi-arch images (amd64 and arm64)
- Images are automatically tagged with branch names and semantic versions
- Pull requests build images but don't publish them
- The `latest` tag is only updated on the default branch
