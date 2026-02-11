# Docker Deployment

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Tyox-all/Weave_Protocol.git
cd Weave_Protocol

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start the stack
docker-compose up -d
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| `weave-api` | 3000 | REST API for all protocols |
| `redis` | 6379 | State storage & message queue |
| `witan-council` | 3001 | Consensus service (optional) |

## Usage

### Basic (API + Redis)

```bash
docker-compose up -d
```

### Full Stack (includes Witan Council)

```bash
docker-compose --profile full up -d
```

### View Logs

```bash
docker-compose logs -f weave-api
```

### Stop

```bash
docker-compose down
```

### Stop and Remove Volumes

```bash
docker-compose down -v
```

## API Endpoints

Once running, the API is available at `http://localhost:3000`:

```bash
# Health check
curl http://localhost:3000/health

# Scan for secrets
curl -X POST http://localhost:3000/api/v1/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "API key: sk-1234567890"}'

# Create thread
curl -X POST http://localhost:3000/api/v1/domere/threads \
  -H "Content-Type: application/json" \
  -d '{"origin_type": "agent", "origin_identity": "gpt-4", "intent": "Process data"}'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGNING_KEY` | (required) | Secret key for signing |
| `SOLANA_RPC_URL` | devnet | Solana RPC endpoint |
| `ETHEREUM_RPC_URL` | - | Ethereum RPC endpoint |
| `MAX_AGENTS` | 10 | Max agents for Witan |
| `DEFAULT_QUORUM` | 0.5 | Consensus quorum |
| `DEFAULT_THRESHOLD` | 0.6 | Approval threshold |

## Building Images

```bash
# Build API
cd api && npm run build
docker build -t weave-api .

# Build Witan
cd witan && npm run build
docker build -t weave-witan .
```
