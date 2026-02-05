// Audit logging for NIST 800-53 AU-12 compliance

export interface AuditEvent {
  timestamp: string;
  tool: string;
  parameters: Record<string, unknown>;
  success: boolean;
  errorMessage?: string;
  durationMs: number;
}

const REDACT_KEYS = ["api_key", "token", "secret", "password", "key", "credential"];

function sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (REDACT_KEYS.some(k => key.toLowerCase().includes(k))) {
      result[key] = "[REDACTED]";
    } else if (typeof value === "object" && value !== null) {
      result[key] = sanitizeParams(value as Record<string, unknown>);
    } else {
      result[key] = value;
    }
  }
  return result;
}

export function logAuditEvent(event: AuditEvent): void {
  const sanitized = {
    type: "audit",
    timestamp: event.timestamp,
    tool: event.tool,
    parameters: sanitizeParams(event.parameters),
    success: event.success,
    durationMs: event.durationMs,
    ...(event.errorMessage && { errorMessage: event.errorMessage }),
  };
  // Log to stderr to avoid interfering with stdio MCP transport
  console.error(JSON.stringify(sanitized));
}

export function createAuditedHandler<T extends Record<string, unknown>>(
  toolName: string,
  handler: (params: T) => Promise<{ content: Array<{ type: "text"; text: string }> }>
): (params: T) => Promise<{ content: Array<{ type: "text"; text: string }> }> {
  return async (params: T) => {
    const startTime = Date.now();
    try {
      const result = await handler(params);
      logAuditEvent({
        timestamp: new Date().toISOString(),
        tool: toolName,
        parameters: params as Record<string, unknown>,
        success: true,
        durationMs: Date.now() - startTime,
      });
      return result;
    } catch (error) {
      logAuditEvent({
        timestamp: new Date().toISOString(),
        tool: toolName,
        parameters: params as Record<string, unknown>,
        success: false,
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        durationMs: Date.now() - startTime,
      });
      throw error;
    }
  };
}
