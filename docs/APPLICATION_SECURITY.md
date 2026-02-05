# Cloudflare MCP API Server - Application Security

## Security Overview

This document describes the security architecture, controls, and considerations for the Cloudflare MCP API Server.

## Threat Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TRUSTED ZONE                                                           │
│  ┌─────────────────┐       ┌─────────────────┐       ┌───────────────┐  │
│  │   AI Client     │ stdio │  MCP Server     │ HTTPS │  Cloudflare   │  │
│  │   (Claude)      │◄─────►│  (Node.js)      │◄─────►│  API          │  │
│  └─────────────────┘       └─────────────────┘       └───────────────┘  │
│                                    │                                     │
│                                    ▼                                     │
│                            ┌───────────────┐                            │
│                            │ Environment   │                            │
│                            │ Variables     │                            │
│                            └───────────────┘                            │
└─────────────────────────────────────────────────────────────────────────┘
```

### Assets Under Protection

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| API Token | HIGH | Environment variable, never logged |
| Account Configuration Data | MEDIUM | Read-only access, no persistence |
| Audit Logs | MEDIUM | Query-only, no modification |
| Zone Settings | MEDIUM | Read-only access |

### Threat Actors

1. **Malicious AI Prompts**: Attempts to exfiltrate token or access unauthorized data
2. **Local Process Attackers**: Other processes on same host
3. **Network Attackers**: MitM on Cloudflare API connection
4. **Supply Chain**: Compromised dependencies

## Security Controls

### Authentication & Authorization

| Control | Implementation | Status |
|---------|----------------|--------|
| API Token Authentication | Bearer token via environment variable | ✅ Implemented |
| Principle of Least Privilege | Read-only token recommended | ✅ Documented |
| Token Validation | Startup check for presence | ✅ Implemented |
| Multi-tenant Isolation | Single-token model per process | ✅ By Design |

### Data Protection

| Control | Implementation | Status |
|---------|----------------|--------|
| TLS for API Calls | HTTPS to api.cloudflare.com | ✅ Enforced |
| No Token Logging | Token not included in logs/errors | ✅ Implemented |
| No Data Persistence | Responses not cached to disk | ✅ By Design |
| Read-Only Operations | No create/update/delete methods | ✅ By Design |

### Input Validation

| Control | Implementation | Status |
|---------|----------------|--------|
| Schema Validation | Zod schemas for all tool inputs | ✅ Implemented |
| Type Checking | TypeScript strict mode | ✅ Enabled |
| Parameter Sanitization | URL encoding via URLSearchParams | ✅ Implemented |

## Security Architecture

### API Token Handling

```typescript
// Token sourced from environment only - never hardcoded
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
if (!apiToken) {
  console.error("Error: CLOUDFLARE_API_TOKEN environment variable is required");
  process.exit(1);
}

// Token used only in Authorization header
headers: {
  Authorization: `Bearer ${this.apiToken}`,
  "Content-Type": "application/json",
}
```

**Security Properties:**
- Token never appears in logs or error messages
- Token loaded once at startup, stored in memory
- Token not passed through MCP protocol to AI clients

### Input Validation Flow

```
AI Request → MCP Protocol → Zod Schema Validation → CloudflareClient → API
                                    │
                                    ▼ (Reject if invalid)
                              ValidationError
```

All tool inputs are validated against Zod schemas before any API call:

```typescript
inputSchema: z.object({
  account_id: z.string().describe("The account ID"),
  zone_id: z.string().describe("The zone ID"),
  // ... strictly typed parameters
})
```

### Transport Security

| Layer | Protocol | Security |
|-------|----------|----------|
| AI ↔ MCP Server | stdio | Process isolation |
| MCP Server ↔ Cloudflare | HTTPS | TLS 1.2+ |

## Known Security Considerations

### 1. Token Exposure Risks

**Risk**: API token could be exposed through:
- Process listing showing environment variables
- Log files if accidentally logged
- Memory dumps
- Configuration files if stored insecurely

**Mitigations**:
- Documentation recommends secure token storage
- Token is not logged anywhere in code
- README warns against committing tokens

### 2. AI-Mediated Access

**Risk**: AI clients have full access to all tools the token permits

**Mitigations**:
- Read-only design prevents destructive actions
- Use tokens with minimal required permissions
- Audit logs available to track API usage

### 3. Dependency Security

**Current Dependencies**:
```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.26.0",
    "zod": "^3.25.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "tsx": "^4.19.0",
    "typescript": "^5.7.0"
  }
}
```

**Risk**: Compromised dependencies could:
- Exfiltrate API token
- Modify API requests
- Inject malicious responses

**Mitigations**:
- Minimal dependency footprint (only 2 runtime deps)
- Both dependencies are well-maintained, widely-used packages
- Regular dependency updates recommended

### 4. Rate Limiting

**Risk**: No client-side rate limiting could lead to:
- API quota exhaustion
- Account-level rate limiting
- Denial of service to other API consumers

**Status**: ⚠️ Not implemented - relies on Cloudflare API rate limits

## Secure Deployment Recommendations

### Token Creation

1. Create a **dedicated API token** for this server
2. Grant **read-only** permissions only
3. Scope to **specific zones/accounts** if possible
4. Set **IP restrictions** if deployment location is static
5. Enable **token expiration** and rotate regularly

### Runtime Security

1. Run with **least-privilege user** (not root)
2. Use **secrets management** (not plaintext env vars in shell history)
3. Enable **process isolation** (containers, VMs)
4. Monitor **Cloudflare audit logs** for API activity
5. Set up **alerting** for unusual API patterns

### Network Security

1. Ensure **outbound HTTPS** to api.cloudflare.com is allowed
2. Consider **egress filtering** to only allow Cloudflare IPs
3. Use **WARP/Zero Trust** if additional network security is needed

## Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| **Authentication** | API token via environment variable |
| **Authorization** | Read-only operations by design |
| **Encryption in Transit** | TLS for all Cloudflare API calls |
| **Encryption at Rest** | No data persisted |
| **Audit Logging** | Available via Cloudflare dashboard |
| **Input Validation** | Zod schema validation |
| **Error Handling** | Graceful error responses, no sensitive data |

## Security Checklist

- [ ] Use a dedicated, read-only API token
- [ ] Store token in secure secrets manager
- [ ] Run as non-root user
- [ ] Keep dependencies updated
- [ ] Monitor Cloudflare audit logs
- [ ] Enable token expiration/rotation
- [ ] Review token permissions periodically
- [ ] Use process isolation (container)

## Incident Response

### Token Compromise

1. **Revoke** the compromised token immediately in Cloudflare dashboard
2. **Create** a new token with same read-only permissions
3. **Update** the MCP server configuration
4. **Review** Cloudflare audit logs for unauthorized access
5. **Investigate** the compromise vector

### Suspicious Activity

1. Check **Cloudflare audit logs** for unusual API patterns
2. Review **token permissions** for scope creep
3. Verify **no write operations** were performed (should be impossible)
4. Consider **rotating token** as precaution
