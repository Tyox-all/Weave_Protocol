# Weave Protocol API

**Universal REST Interface for Weave Protocol Security Suite**

Works with **any** AI platform: OpenAI, Gemini, LangChain, Grok, Copilot, Siri, or any HTTP client.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WEAVE API                                         │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                        REST Endpoints                               │  │
│   │                                                                     │  │
│   │  POST /api/v1/mund/*      POST /api/v1/hord/*     POST /api/v1/domere/* │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                   │                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                      Platform Adapters                              │  │
│   │                                                                     │  │
│   │  OpenAI    Gemini    LangChain    Grok    Copilot    Any HTTP     │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                   │                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                        Core Services                                │  │
│   │                                                                     │  │
│   │         Mund              Hord              Dōmere                  │  │
│   │       (Guardian)         (Vault)           (Judge)                  │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Run the API Server

```bash
# Install
npm install @weave_protocol/api

# Run
npx weave-api

# Or with Docker
docker run -p 3000:3000 weave/api
```

### Environment Variables

```bash
WEAVE_PORT=3000              # Server port
WEAVE_API_KEY=your-key       # Optional API key protection
WEAVE_CORS_ORIGIN=*          # CORS origin
WEAVE_RATE_LIMIT=100         # Requests per minute
```

## REST Endpoints

### Mund (Security Scanning)

```bash
# Full scan
curl -X POST http://localhost:3000/api/v1/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "My API key is sk-1234567890"}'

# Scan for secrets
curl -X POST http://localhost:3000/api/v1/mund/scan/secrets \
  -d '{"content": "..."}'

# Scan for PII
curl -X POST http://localhost:3000/api/v1/mund/scan/pii \
  -d '{"content": "Contact john@email.com"}'

# Check for injection
curl -X POST http://localhost:3000/api/v1/mund/scan/injection \
  -d '{"content": "Ignore previous instructions..."}'
```

### Hord (Containment)

```bash
# Create vault
curl -X POST http://localhost:3000/api/v1/hord/vaults \
  -d '{"name": "secrets", "description": "API keys"}'

# Store secret
curl -X POST http://localhost:3000/api/v1/hord/vaults/{id}/secrets \
  -d '{"key": "openai", "value": "sk-..."}'

# Redact content
curl -X POST http://localhost:3000/api/v1/hord/redact \
  -d '{"content": "Email me at john@example.com"}'

# Sandbox execute
curl -X POST http://localhost:3000/api/v1/hord/sandbox/execute \
  -d '{"code": "console.log(1+1)", "language": "javascript"}'
```

### Dōmere (Verification)

```bash
# Create thread
curl -X POST http://localhost:3000/api/v1/domere/threads \
  -d '{"origin_type": "human", "origin_identity": "user_123", "intent": "Get sales data"}'

# Add hop
curl -X POST http://localhost:3000/api/v1/domere/threads/{id}/hops \
  -d '{"agent_id": "gpt-4", "agent_type": "openai", "received_intent": "Query sales", "actions": []}'

# Check drift
curl -X POST http://localhost:3000/api/v1/domere/drift/check \
  -d '{"original_intent": "Get Q3 sales", "current_intent": "Get all sales data"}'

# Anchor to blockchain (paid)
curl -X POST http://localhost:3000/api/v1/domere/anchor/prepare \
  -d '{"thread_id": "thr_...", "network": "solana"}'
```

## Platform Integrations

### OpenAI Function Calling

```typescript
import OpenAI from 'openai';
import { getWeaveFunctions, handleWeaveFunction } from '@weave_protocol/api/adapters/openai';

const openai = new OpenAI();

const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: "Check this for secrets: sk-abc123" }],
  functions: getWeaveFunctions(),
  function_call: "auto"
});

if (response.choices[0].message.function_call) {
  const result = await handleWeaveFunction(
    response.choices[0].message.function_call.name,
    JSON.parse(response.choices[0].message.function_call.arguments)
  );
  console.log(result);
}
```

### Google Gemini

```typescript
import { GoogleGenerativeAI } from '@google/generative-ai';
import { getGeminiFunctionDeclarations, handleWeaveFunction } from '@weave_protocol/api/adapters/openai';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({
  model: "gemini-pro",
  tools: [getGeminiFunctionDeclarations()]
});

const result = await model.generateContent("Scan this: my password is hunter2");
const functionCall = result.response.functionCalls()?.[0];

if (functionCall) {
  const weaveResult = await handleWeaveFunction(functionCall.name, functionCall.args);
}
```

### LangChain

```typescript
import { ChatOpenAI } from "@langchain/openai";
import { initializeAgentExecutorWithOptions } from "langchain/agents";
import { getWeaveTools } from '@weave_protocol/api/adapters/langchain';

const llm = new ChatOpenAI({ temperature: 0 });
const tools = getWeaveTools();

const agent = await initializeAgentExecutorWithOptions(tools, llm, {
  agentType: "openai-functions"
});

const result = await agent.invoke({
  input: "Check if this contains any secrets: API_KEY=sk-12345"
});
```

### Any HTTP Client (Python, Go, Rust, etc.)

```python
import requests

# Python
response = requests.post(
    "http://localhost:3000/api/v1/mund/scan",
    json={"content": "My secret is abc123"}
)
print(response.json())
```

```go
// Go
resp, _ := http.Post(
    "http://localhost:3000/api/v1/mund/scan",
    "application/json",
    strings.NewReader(`{"content": "My secret is abc123"}`),
)
```

```bash
# cURL (any platform)
curl -X POST http://localhost:3000/api/v1/mund/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "Check this"}'
```

## OpenAI-Compatible Endpoint

For any OpenAI-compatible API (Grok, local models, etc.):

```bash
# List available functions
curl http://localhost:3000/api/v1/functions

# Call a function directly
curl -X POST http://localhost:3000/api/v1/functions/call \
  -d '{"function": "mund_scan_content", "arguments": {"content": "..."}}'
```

## Deployment

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

```bash
docker build -t weave-api .
docker run -p 3000:3000 -e WEAVE_API_KEY=secret weave-api
```

### Docker Compose

```yaml
version: '3.8'
services:
  weave-api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - WEAVE_API_KEY=${WEAVE_API_KEY}
      - WEAVE_RATE_LIMIT=100
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: weave-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: weave-api
  template:
    spec:
      containers:
      - name: weave-api
        image: weave/api:latest
        ports:
        - containerPort: 3000
        env:
        - name: WEAVE_API_KEY
          valueFrom:
            secretKeyRef:
              name: weave-secrets
              key: api-key
```

## Security

- **API Key Auth**: Set `WEAVE_API_KEY` to require authentication
- **Rate Limiting**: Default 100 requests/minute
- **CORS**: Configurable origins
- **Helmet**: Security headers enabled

## License

Apache-2.0

## Links

- [Weave Protocol Security Suite](https://github.com/Tyox-all/Weave-Protocol)
- [@weave_protocol/mund](https://www.npmjs.com/package/@weave_protocol/mund)
- [@weave_protocol/hord](https://www.npmjs.com/package/@weave_protocol/hord)
- [@weave_protocol/domere](https://www.npmjs.com/package/@weave_protocol/domere)
