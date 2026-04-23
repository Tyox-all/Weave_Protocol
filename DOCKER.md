# Running Weave Protocol with Docker

Weave Protocol packages can be run as Docker containers for production deployments, CI/CD environments, and air-gapped setups. This guide covers the API server (which exposes all packages over REST) and the individual MCP servers.

---

## Quick start with Docker Compose

```bash
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

cp .env.example .env  # edit if you want to set WEAVE_API_KEY etc.
docker-compose up -d

# Open the dashboard
open http://localhost:3000/dashboard
```

This brings up:

- **API server** (`@weave_protocol/api`) on port 3000 — REST endpoints + monitoring dashboard
- All MCP-compatible packages reachable through the API: Mund, Hord, Domere, Hundredmen

---

## Running the API server alone

```bash
docker run -d \
  --name weave-api \
  -p 3000:3000 \
  -e WEAVE_API_KEY=your-key \
  weave-protocol/api:latest
```

Then verify:

```bash
curl http://localhost:3000/health
curl http://localhost:3000/stats
```

---

## Running individual MCP servers

For users who want to run a specific MCP server in a container (rather than via `npx`), each package can be wrapped in a minimal Node.js image:

```dockerfile
FROM node:20-alpine
RUN npm install -g @weave_protocol/tollere
ENTRYPOINT ["weave-tollere"]
```

Build and run:

```bash
docker build -t weave-tollere .
docker run --rm weave-tollere scan
```

Same pattern works for `@weave_protocol/mund`, `@weave_protocol/hord`, etc.

---

## Configuration

The API server reads the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WEAVE_PORT` | `3000` | HTTP port |
| `WEAVE_HOST` | `0.0.0.0` | Bind address |
| `WEAVE_API_KEY` | _(none)_ | Optional API key for authenticated endpoints |
| `WEAVE_CORS_ORIGIN` | `*` | CORS allowed origins |
| `WEAVE_RATE_LIMIT` | `100` | Requests per minute on `/api/*` routes |

The dashboard (`/dashboard`) is exempt from rate limiting and authentication so internal monitoring tools can poll without keys.

---

## Production considerations

### Reverse proxy

In production, run the API behind a reverse proxy (nginx, Caddy, Traefik) and terminate TLS there. The API does not implement TLS itself.

Example nginx config:

```nginx
server {
    listen 443 ssl http2;
    server_name weave.example.com;

    ssl_certificate     /etc/ssl/certs/weave.crt;
    ssl_certificate_key /etc/ssl/private/weave.key;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Tollere in CI/CD

The most common production use of Docker for Weave Protocol is running Tollere as a pre-install gate in CI:

```yaml
# .github/workflows/security.yml
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Tollere
        run: |
          docker run --rm -v $PWD:/repo -w /repo \
            node:20-alpine \
            sh -c 'npm install -g @weave_protocol/tollere && weave-tollere scan'
```

Exit codes: `0` = clean, `1` = warnings, `2` = blocked. Configure your pipeline to fail on `2`.

### Hord in production

Hord uses in-memory keys by default. For production, mount a persistent volume for vault data and configure key derivation parameters appropriate for your threat model:

```bash
docker run -d \
  --name weave-hord \
  -v hord-data:/var/lib/hord \
  -e HORD_ARGON2_MEMORY_KIB=131072 \
  -e HORD_ARGON2_ITERATIONS=4 \
  weave-protocol/hord:latest
```

---

## Building from source

```bash
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

# Build the API container
docker build -t weave-protocol/api:dev -f api/Dockerfile .

# Build the Witan container
docker build -t weave-protocol/witan:dev -f witan/Dockerfile .
```

---

## Image hardening

The published images are based on `node:20-alpine` for minimal attack surface. They run as a non-root user (`node`) and contain only the required runtime dependencies.

If you need stricter isolation:

- Run with `--read-only` and a tmpfs for `/tmp`
- Drop capabilities: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` (only if binding port < 1024)
- Use a seccomp profile

---

## Troubleshooting

**Dashboard shows "Failed to fetch":** The dashboard polls `/stats`, `/feed`, etc. If you've put a reverse proxy in front and authenticated those routes, the dashboard will fail. Either expose them unauthenticated to internal traffic or move the dashboard inside your network.

**MCP server containers exit immediately:** MCP servers communicate over stdio, not HTTP. They expect a parent process (Claude Desktop, Claude Code, etc.) to attach. Running them detached with `docker run -d` will not work — use `docker run -i` and attach a client.

**Tollere returns "Could not fetch metadata":** The container needs outbound internet access to query the npm registry, OSV.dev, Docker Hub, and the VS Code Marketplace. Verify your firewall rules.

---

For more information, see the individual package READMEs in the monorepo.
