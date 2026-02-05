// GraphQL query validation for NIST 800-53 SI-10 (Input Validation) compliance
// Enforces read-only operations and blocks introspection

const BLOCKED_PATTERNS = [
  /__schema/i,       // Introspection (information disclosure)
  /__type/i,         // Type introspection
  /mutation\s*[{(]/i, // Block mutations
  /subscription\s*[{(]/i, // Block subscriptions
];

const ALLOWED_OPERATION_STARTS = [
  "query",  // Named query
  "{",      // Anonymous query
];

export function validateGraphQLQuery(query: string): void {
  if (!query || typeof query !== "string") {
    throw new Error("GraphQL query must be a non-empty string");
  }

  const trimmed = query.trim();

  if (trimmed.length === 0) {
    throw new Error("GraphQL query cannot be empty");
  }

  // Check for blocked patterns
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(trimmed)) {
      throw new Error("GraphQL query contains disallowed operations");
    }
  }

  // Ensure query starts with allowed operation
  const lowerTrimmed = trimmed.toLowerCase();
  const startsWithAllowed = ALLOWED_OPERATION_STARTS.some(
    (op) => lowerTrimmed.startsWith(op)
  );

  if (!startsWithAllowed) {
    throw new Error("GraphQL query must be a read-only query operation");
  }
}

export function validateGraphQLVariables(variables: string): Record<string, unknown> {
  if (!variables) {
    return {};
  }

  try {
    const parsed = JSON.parse(variables);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("GraphQL variables must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error("Invalid JSON in GraphQL variables parameter");
    }
    throw error;
  }
}
