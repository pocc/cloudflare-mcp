# Contributing to Cloudflare MCP API Server

Thank you for your interest in contributing! This document provides guidelines for contributions.

## Code of Conduct

Be respectful and constructive in all interactions.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Install dependencies: `npm install`
4. Create a feature branch: `git checkout -b feature/your-feature`

## Development

### Prerequisites

- Node.js ≥18.0.0
- A Cloudflare API token (read-only permissions)

### Running Locally

```bash
export CLOUDFLARE_API_TOKEN="your-token"
npm run dev
```

### Type Checking

```bash
npm run lint
```

## Adding New Tools

When adding new Cloudflare API endpoints:

1. **Add tool definition** in `src/tools.ts`:
   ```typescript
   new_tool_name: {
     name: "new_tool_name",
     description: "Description of what this tool does",
     inputSchema: z.object({
       account_id: z.string().describe("The account ID"),
       // ... other parameters
     }),
   },
   ```

2. **Add API client method** in `src/api-client.ts`:
   ```typescript
   async newToolName(accountId: string) {
     return this.request<any>("GET", `/accounts/${accountId}/new/endpoint`);
   }
   ```

3. **Register the tool** in `src/index.ts`:
   ```typescript
   server.tool(
     toolDefinitions.new_tool_name.name,
     toolDefinitions.new_tool_name.description,
     toolDefinitions.new_tool_name.inputSchema.shape,
     async ({ account_id }) => {
       const result = await client.newToolName(account_id);
       return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
     }
   );
   ```

4. **Update documentation** in `docs/API_ENDPOINTS.md`

## Security Requirements

All contributions must maintain FedRAMP High compliance:

- **No write operations** - This is a read-only server by design
- **Input validation** - All parameters must use Zod schemas
- **No secrets in code** - API tokens come from environment variables only
- **Safe error messages** - Never expose internal details or stack traces

## Pull Request Process

1. Ensure `npm run lint` passes with no errors
2. Update documentation if adding new features
3. Write clear commit messages
4. Reference any related issues

## Commit Message Format

Use semantic commit messages:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance tasks

Example:
```
feat: add support for Magic Transit endpoints

Adds 10 new tools for IPsec tunnels, GRE tunnels, routes, connectors, and sites.
```

## Questions?

Open an issue for questions or discussions.
