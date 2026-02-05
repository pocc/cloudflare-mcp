# Cloudflare MCP API Server (Enterprise Edition)

[![Security: FedRAMP High](https://img.shields.io/badge/Security-FedRAMP%20High-blue)](./docs/SECURITY_REVIEW.md)
[![Tools: 354](https://img.shields.io/badge/Tools-354-green)](#api-coverage)
[![NIST 800-53](https://img.shields.io/badge/NIST-800--53%20Rev.5-orange)](./docs/SECURITY_FIXES.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A high-performance Model Context Protocol (MCP) server providing AI assistants with **read-only access** to the Cloudflare ecosystem. Query your entire Cloudflare infrastructure using natural language through Claude, Cursor, or any MCP-compatible client. Inspired by [mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare).

## Security-First Design

This server implements NIST 800-53 Rev. 5 controls for FedRAMP High environments:

| Control | Implementation | File |
|---------|----------------|------|
| **AU-12** (Audit Generation) | All API calls logged with sensitive data redaction | `src/audit-logger.ts` |
| **SC-5** (DoS Protection) | Token bucket rate limiting (100 burst, 10/sec) | `src/rate-limiter.ts` |
| **SI-10** (Input Validation) | Zod schemas + GraphQL mutation blocking | `src/graphql-validator.ts` |
| **SI-11** (Error Handling) | Safe error messages, no stack traces | `src/api-client.ts` |
| **IA-5(7)** (Token Protection) | XOR obfuscation in memory | `src/api-client.ts` |

## Why Use This?
- **Infrastructure discovery**: "What DNS records exist across all my zones?"
- **Security audits**: "Which zones don't have WAF enabled?" or "Show me all rate limiting rules"
- **Troubleshooting**: "What are the SSL settings for example.com?"
- **Documentation**: Generate configuration reports by asking questions
- **Learning**: Explore your Cloudflare setup without memorizing API endpoints

## Features

- **354 read-only tools** covering the entire Cloudflare API surface (as of 2026-02-05)
- **Zero write operations** - cannot modify any configurations (safe to use)
- **Natural language queries** - ask questions, get answers
- **Built-in security** - rate limiting, audit logging, token protection

### API Coverage

| Category | Examples |
|----------|----------|
| **Core** | Accounts, Zones, DNS, Settings |
| **Security** | WAF, Firewall, Bot Management, Page Shield, DDoS |
| **SSL/TLS** | Certificates, Universal SSL, Custom Certs, mTLS |
| **Performance** | Argo, Cache, Load Balancing, Waiting Rooms |
| **Zero Trust** | Access Apps, Gateway, Devices, Tunnels, DEX |
| **Developer Platform** | Workers, Pages, D1, R2, KV, Queues, Durable Objects |
| **Analytics** | Dashboard, GraphQL, Audit Logs |
| **Enterprise** | Cloudforce One, Magic Transit, Spectrum, Custom Hostnames |

## Quick Start

### 1. Install

```bash
git clone https://github.com/pocc/cloudlfare-mcp.git
cd cloudflare-mcp
npm install
npm run build
```

### 2. Create API Token

1. Go to [Cloudflare Dashboard → API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use **Custom Token** with **read-only** permissions:
   - Account Settings: Read
   - Zone: Read  
   - Zone Settings: Read
   - DNS: Read
   - SSL and Certificates: Read
   - Firewall Services: Read
   - Analytics: Read
   - Access: Apps and Policies: Read
   - Worker Scripts: Read
   - Load Balancers: Read
   - *(add more as needed for your use case)*

### 3. Configure Your MCP Client

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "node",
      "args": ["/path/to/cloudflare-mcp/dist/index.js"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "your-api-token-here"
      }
    }
  }
}
```

#### Cursor / Other MCP Clients

```bash
CLOUDFLARE_API_TOKEN="your-token" node dist/index.js
```

## Example Queries

Once connected, ask natural language questions:

**Discovery**
- "List all my zones and their status"
- "What Workers do I have deployed?"
- "Show me all Access applications"

**Security Audit**
- "Which zones have bot management enabled?"
- "What WAF rules are configured on example.com?"
- "List all rate limiting rules across my account"
- "Show audit logs from the last 24 hours filtered by user@example.com"

**Troubleshooting**
- "What are the SSL settings for example.com?"
- "Is Argo Smart Routing enabled on my zones?"
- "What DNS records exist for api.example.com?"
- "Show me the load balancer configuration for production"

**Zero Trust**
- "List all Cloudflare Tunnel connections"
- "What Access policies protect my apps?"
- "Show Gateway network policies"
- "What devices are registered in my Zero Trust org?"

## Security

| Feature | Description |
|---------|-------------|
| **Read-Only** | Cannot create, update, or delete any resources |
| **Rate Limited** | Built-in token bucket (100 burst, 10/sec) |
| **Audit Logged** | All API calls logged with sensitive data redacted |
| **Token Protected** | API token XOR-obfuscated in memory |
| **Input Validated** | Zod schemas + GraphQL query validation |

**Best Practices:**
- Use the principle of least privilege when creating tokens
- Never commit tokens to version control
- Rotate tokens periodically

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](./docs/ARCHITECTURE.md) | Technical design and data flow |
| [API Reference](./docs/API_ENDPOINTS.md) | Complete list of 354 tools |
| [Security Review](./docs/SECURITY_REVIEW.md) | FedRAMP compliance details |
| [Security Fixes](./docs/SECURITY_FIXES.md) | NIST control implementations |

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

MIT
