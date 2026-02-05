# Cloudflare MCP API Server - Architecture

## Overview

The Cloudflare MCP API Server is a **Model Context Protocol (MCP)** server that provides AI assistants (like Claude) with **read-only** access to the Cloudflare API. It enables querying Cloudflare configurations, audit logs, SSL certificates, rate limiting rules, and 350+ other API endpoints.

## Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Runtime | Node.js | ≥18.0.0 |
| Language | TypeScript | 5.7+ |
| Module System | ESM (NodeNext) |  |
| MCP SDK | @modelcontextprotocol/sdk | ^1.26.0 |
| Schema Validation | Zod | ^3.25.0 |
| Transport | stdio (stdin/stdout) |  |

## Project Structure

```
cloudflare-mcp/
├── src/
│   ├── index.ts          # Main entry point, MCP server setup, tool registration
│   ├── api-client.ts     # Cloudflare API client with security features
│   ├── tools.ts          # Tool definitions with Zod schemas
│   ├── rate-limiter.ts   # Token bucket rate limiter
│   ├── audit-logger.ts   # Audit logging with redaction
│   └── graphql-validator.ts  # GraphQL query validation
├── context/
│   ├── API_ENDPOINTS.md  # Cloudflare API reference documentation
│   └── ARCHITECTURE.md   # This file
├── dist/                 # Compiled JavaScript output
├── package.json
├── tsconfig.json
└── README.md
```

## Core Components

### 1. MCP Server (`src/index.ts`)

The main server orchestrates:
- **Environment validation**: Requires `CLOUDFLARE_API_TOKEN` environment variable
- **Tool registration**: Registers 354 tools with the MCP server
- **Transport layer**: Uses stdio for communication with AI clients

```typescript
const server = new McpServer({
  name: "cloudflare-api",
  version: "1.0.0",
});

// Each tool follows this pattern:
server.tool(
  toolDefinitions.TOOL_NAME.name,
  toolDefinitions.TOOL_NAME.description,
  toolDefinitions.TOOL_NAME.inputSchema.shape,
  async (params) => {
    const result = await client.apiMethod(params);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);
```

### 2. API Client (`src/api-client.ts`)

A typed HTTP client for the Cloudflare API:

- **Base URL**: `https://api.cloudflare.com/client/v4`
- **Authentication**: Bearer token via `Authorization` header
- **Response handling**: Parses standard Cloudflare API response format
- **Error handling**: Extracts error messages from API responses

```typescript
export class CloudflareClient {
  private apiToken: string;

  private async request<T>(
    method: string,
    endpoint: string,
    params?: Record<string, string | number | undefined>
  ): Promise<CloudflareResponse<T>> {
    // Builds URL with query params
    // Sends authenticated request
    // Handles errors
  }
}
```

**API Coverage** (organized by category):
- **Accounts**: List, get, members, roles
- **Audit Logs**: Query with filtering
- **Zones**: List, get, settings
- **SSL/TLS**: Certificates, verification, Universal SSL, Keyless SSL
- **Rate Limiting**: Modern WAF rulesets, legacy rules
- **WAF/Firewall**: Custom rules, managed rules, filters
- **DNS**: Records
- **Workers**: Scripts, routes, services, secrets, deployments
- **Load Balancing**: Load balancers, pools, monitors
- **Zero Trust**: Access apps, policies, groups, Gateway, devices
- **Developer Platform**: D1, R2, KV, Durable Objects, Queues, Pages
- **Security**: Page Shield, Security Center, API Shield, Bot Management
- **Analytics**: Dashboard, GraphQL
- **And 40+ more endpoint categories**

### 3. Tool Definitions (`src/tools.ts`)

Zod-based schema definitions for all 354 tools:

```typescript
export const toolDefinitions = {
  list_zones: {
    name: "list_zones",
    description: "List all zones (domains) in the account",
    inputSchema: z.object({
      account_id: z.string().optional().describe("Filter by account ID"),
      name: z.string().optional().describe("Filter by zone name"),
      status: z.string().optional().describe("Filter by status"),
      per_page: z.number().optional().describe("Results per page"),
      page: z.number().optional().describe("Page number"),
    }),
  },
  // ... 353 more tools
};
```

## Data Flow

```
┌─────────────────┐     stdio      ┌──────────────────┐      HTTPS     ┌─────────────────┐
│   AI Client     │ ◄────────────► │  MCP Server      │ ◄────────────► │ Cloudflare API  │
│ (Claude, etc.)  │                │  (Node.js)       │                │ api.cloudflare  │
└─────────────────┘                └──────────────────┘                └─────────────────┘
                                           │
                                           ▼
                                   ┌──────────────────┐
                                   │ Environment Var  │
                                   │ CLOUDFLARE_API_  │
                                   │ TOKEN            │
                                   └──────────────────┘
```

1. **AI Client** sends tool call request via stdio
2. **MCP Server** validates input against Zod schema
3. **API Client** makes authenticated HTTPS request to Cloudflare
4. **Response** flows back through the same path as JSON

## Authentication Model

The server uses a **single API token** model:
- Token is read from `CLOUDFLARE_API_TOKEN` environment variable
- Token is validated at startup (fails fast if missing)
- Token is used for all API requests via `Authorization: Bearer <token>` header
- No token refresh or rotation (static for lifetime of server process)

### Required Token Permissions

| Permission | Scope | Required For |
|------------|-------|--------------|
| Account Settings | Read | Account info, members, roles |
| Zone | Read | Zone list, details |
| Zone Settings | Read | All zone configurations |
| DNS | Read | DNS records |
| SSL and Certificates | Read | SSL settings, certificates |
| Firewall Services | Read | WAF, firewall rules |
| Analytics | Read | Zone analytics, GraphQL |
| Access | Read | Access apps, policies |
| Worker Scripts | Read | Workers, routes |
| Load Balancers | Read | Load balancers, pools |

## Build & Deployment

### Development
```bash
npm install
CLOUDFLARE_API_TOKEN="token" npm run dev  # Uses tsx for hot reload
```

### Production Build
```bash
npm run build   # TypeScript compilation to dist/
npm start       # Run compiled JavaScript
```

### Claude Desktop Integration
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

## Design Principles

1. **Read-Only**: No write operations to prevent accidental mutations
2. **Comprehensive Coverage**: 354 tools covering most of Cloudflare's API surface
3. **Type Safety**: Full TypeScript with Zod runtime validation
4. **Minimal Dependencies**: Only MCP SDK and Zod
5. **Standard Transport**: stdio for universal MCP client compatibility
6. **Fail Fast**: Validates token presence at startup

## Error Handling

### Startup Errors
- Missing `CLOUDFLARE_API_TOKEN`: Process exits with code 1

### Runtime Errors
- API errors are extracted from Cloudflare response and thrown
- Network errors propagate to MCP client
- Invalid tool parameters rejected by Zod validation

```typescript
if (!data.success) {
  const errorMsg = data.errors.map((e) => e.message).join(", ");
  throw new Error(`Cloudflare API error: ${errorMsg}`);
}
```

## Limitations

1. **No Write Operations**: By design, cannot create/update/delete resources
2. **Single Token**: Cannot switch between tokens/accounts at runtime
3. **No Caching**: Each request hits Cloudflare API directly
4. **Built-in Rate Limiting**: Token bucket algorithm (100 burst, 10/sec sustained)
5. **Synchronous Tools**: Each tool waits for API response

## Security Features

| Feature | Implementation | NIST Control |
|---------|----------------|---------------|
| Rate Limiting | Token bucket algorithm | SC-5 (DoS Protection) |
| Audit Logging | All API calls logged with redaction | AU-12 (Audit Generation) |
| Token Protection | XOR obfuscation in memory | IA-5(7) (Authenticator Protection) |
| Input Validation | Zod schemas + GraphQL validation | SI-10 (Input Validation) |
| Safe Errors | Generic error messages | SI-11 (Error Handling) |

## Future Considerations

- Response caching for frequently-accessed data
- Multi-token support for multi-account scenarios
- Streaming support for large responses
- Webhook/real-time event support
