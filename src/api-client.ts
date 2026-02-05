// Cloudflare API Client
// Security: V-001, V-002, V-003, V-004, V-006 fixes applied

import { randomBytes } from "crypto";
import { RateLimiter } from "./rate-limiter.js";
import { validateGraphQLQuery, validateGraphQLVariables } from "./graphql-validator.js";
import { logAuditEvent } from "./audit-logger.js";

const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// V-002: Safe error messages to prevent information disclosure (SI-11)
const SAFE_ERROR_CODES: Record<number, string> = {
  6003: "Invalid request parameters",
  6100: "Invalid request headers",
  6200: "Invalid request body",
  7000: "Authentication error",
  7003: "Forbidden - insufficient permissions",
  9109: "Resource not found",
  10000: "Rate limit exceeded",
};

export interface CloudflareConfig {
  apiToken: string;
}

export interface CloudflareResponse<T> {
  success: boolean;
  errors: Array<{ code: number; message: string }>;
  messages: string[];
  result: T;
  result_info?: {
    page: number;
    per_page: number;
    total_pages: number;
    count: number;
    total_count: number;
  };
}

export class CloudflareClient {
  // V-004: Token obfuscation in memory (IA-5(7))
  private tokenXorKey: Buffer;
  private obfuscatedToken: Buffer;
  // V-003: Rate limiting (SC-5)
  private rateLimiter: RateLimiter;

  constructor(config: CloudflareConfig) {
    // V-004: XOR-obfuscate token in memory
    const tokenBuffer = Buffer.from(config.apiToken, "utf-8");
    this.tokenXorKey = randomBytes(tokenBuffer.length);
    this.obfuscatedToken = Buffer.alloc(tokenBuffer.length);
    for (let i = 0; i < tokenBuffer.length; i++) {
      this.obfuscatedToken[i] = tokenBuffer[i] ^ this.tokenXorKey[i];
    }
    // V-003: Initialize rate limiter (100 burst, 10/sec sustained)
    this.rateLimiter = new RateLimiter(100, 10);
  }

  // V-004: Reconstruct token only when needed
  private getToken(): string {
    const token = Buffer.alloc(this.obfuscatedToken.length);
    for (let i = 0; i < this.obfuscatedToken.length; i++) {
      token[i] = this.obfuscatedToken[i] ^ this.tokenXorKey[i];
    }
    const result = token.toString("utf-8");
    token.fill(0); // Clear temporary buffer
    return result;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    params?: Record<string, string | number | undefined>
  ): Promise<CloudflareResponse<T>> {
    // V-003: Wait for rate limit token
    await this.rateLimiter.acquire();

    const url = new URL(`${CF_API_BASE}${endpoint}`);
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    // V-001: Audit logging (AU-12)
    const startTime = Date.now();
    let success = false;
    let errorMessage: string | undefined;

    try {
      const response = await fetch(url.toString(), {
        method,
        headers: {
          Authorization: `Bearer ${this.getToken()}`,
          "Content-Type": "application/json",
        },
      });

      const data = await response.json() as CloudflareResponse<T>;
      
      if (!data.success) {
        // V-002: Map error codes to safe messages, fallback to generic
        const safeMessages = data.errors.map((e) =>
          SAFE_ERROR_CODES[e.code] ?? "An error occurred processing your request"
        );
        const uniqueMessages = [...new Set(safeMessages)];
        errorMessage = uniqueMessages.join("; ");
        throw new Error(`Cloudflare API error: ${errorMessage}`);
      }

      success = true;
      return data;
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : "Unknown error";
      throw error;
    } finally {
      // V-001: Log audit event for all API calls
      logAuditEvent({
        timestamp: new Date().toISOString(),
        tool: `${method} ${endpoint}`,
        parameters: params ?? {},
        success,
        durationMs: Date.now() - startTime,
        ...(errorMessage && { errorMessage }),
      });
    }
  }

  // ============ ACCOUNTS ============
  async listAccounts() {
    return this.request<any[]>("GET", "/accounts");
  }

  async getAccount(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}`);
  }

  async listAccountMembers(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/members`);
  }

  // ============ AUDIT LOGS ============
  async getAuditLogs(
    accountId: string,
    params?: {
      since?: string;
      before?: string;
      actor_email?: string;
      actor_ip?: string;
      action_type?: string;
      zone_name?: string;
      per_page?: number;
      page?: number;
    }
  ) {
    const queryParams: Record<string, string | number | undefined> = {};
    if (params?.since) queryParams.since = params.since;
    if (params?.before) queryParams.before = params.before;
    if (params?.actor_email) queryParams["actor.email"] = params.actor_email;
    if (params?.actor_ip) queryParams["actor.ip"] = params.actor_ip;
    if (params?.action_type) queryParams["action.type"] = params.action_type;
    if (params?.zone_name) queryParams["zone.name"] = params.zone_name;
    if (params?.per_page) queryParams.per_page = params.per_page;
    if (params?.page) queryParams.page = params.page;

    return this.request<any[]>("GET", `/accounts/${accountId}/audit_logs`, queryParams);
  }

  // ============ ZONES ============
  async listZones(params?: {
    account_id?: string;
    name?: string;
    status?: string;
    per_page?: number;
    page?: number;
  }) {
    return this.request<any[]>("GET", "/zones", params as Record<string, string | number | undefined>);
  }

  async getZone(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}`);
  }

  async getZoneSettings(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/settings`);
  }

  // ============ SSL/TLS ============
  async getSSLSettings(zoneId: string) {
    const [ssl, minTls, tls13, universal] = await Promise.all([
      this.request<any>("GET", `/zones/${zoneId}/settings/ssl`),
      this.request<any>("GET", `/zones/${zoneId}/settings/min_tls_version`),
      this.request<any>("GET", `/zones/${zoneId}/settings/tls_1_3`),
      this.getUniversalSSLSettings(zoneId).catch(() => null),
    ]);

    return {
      ssl_mode: ssl.result,
      min_tls_version: minTls.result,
      tls_1_3: tls13.result,
      universal_ssl: universal?.result,
    };
  }

  async listCertificatePacks(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/ssl/certificate_packs`);
  }

  async getSSLVerification(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/ssl/verification`);
  }

  async listCustomCertificates(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/custom_certificates`);
  }

  async getUniversalSSLSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/ssl/universal/settings`);
  }

  // ============ RATE LIMITING ============
  async getRateLimitingRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_ratelimit/entrypoint`);
  }

  async listLegacyRateLimits(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/rate_limits`);
  }

  // ============ RULESETS ============
  async listZoneRulesets(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/rulesets`);
  }

  async getRuleset(zoneId: string, rulesetId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/${rulesetId}`);
  }

  async getWAFCustomRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`);
  }

  async getWAFManagedRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_request_firewall_managed/entrypoint`);
  }

  // ============ DNS ============
  async listDNSRecords(zoneId: string, params?: { type?: string; name?: string; per_page?: number }) {
    return this.request<any[]>("GET", `/zones/${zoneId}/dns_records`, params as Record<string, string | number | undefined>);
  }

  // ============ FIREWALL ============
  async listFirewallRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/firewall/rules`);
  }

  // ============ PAGE RULES ============
  async listPageRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/pagerules`);
  }

  // ============ WORKERS ============
  async listWorkers(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workers/scripts`);
  }

  async listWorkerRoutes(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/workers/routes`);
  }

  // ============ LOAD BALANCING ============
  async listLoadBalancers(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/load_balancers`);
  }

  async listOriginPools(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/load_balancers/pools`);
  }

  // ============ CUSTOM HOSTNAMES ============
  async listCustomHostnames(zoneId: string, params?: { hostname?: string; per_page?: number }) {
    return this.request<any[]>("GET", `/zones/${zoneId}/custom_hostnames`, params as Record<string, string | number | undefined>);
  }

  // ============ ACCESS ============
  async listAccessApps(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/apps`);
  }

  async listAccessPolicies(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/policies`);
  }

  // ============ BOT MANAGEMENT ============
  async getBotManagement(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/bot_management`);
  }

  // ============ ARGO ============
  async getArgoSettings(zoneId: string) {
    const [smartRouting, tieredCaching] = await Promise.all([
      this.request<any>("GET", `/zones/${zoneId}/argo/smart_routing`).catch(() => null),
      this.request<any>("GET", `/zones/${zoneId}/argo/tiered_caching`).catch(() => null),
    ]);

    return {
      smart_routing: smartRouting?.result,
      tiered_caching: tieredCaching?.result,
    };
  }

  // ============ WAITING ROOM ============
  async listWaitingRooms(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/waiting_rooms`);
  }

  // ============ CACHE ============
  async getCacheSettings(zoneId: string) {
    const [cacheLevel, browserCacheTTL] = await Promise.all([
      this.request<any>("GET", `/zones/${zoneId}/settings/cache_level`),
      this.request<any>("GET", `/zones/${zoneId}/settings/browser_cache_ttl`),
    ]);

    return {
      cache_level: cacheLevel.result,
      browser_cache_ttl: browserCacheTTL.result,
    };
  }

  // ============ ANALYTICS ============
  async getZoneAnalytics(zoneId: string, params?: { since?: string; until?: string }) {
    return this.request<any>("GET", `/zones/${zoneId}/analytics/dashboard`, params as Record<string, string | number | undefined>);
  }

  async getAnalyticsByColo(zoneId: string, params?: { since?: string; until?: string }) {
    return this.request<any>("GET", `/zones/${zoneId}/analytics/colos`, params as Record<string, string | number | undefined>);
  }

  async graphqlAnalytics(query: string, variables?: string) {
    // V-006: Validate GraphQL query (SI-10)
    validateGraphQLQuery(query);
    
    // V-003: Wait for rate limit token
    await this.rateLimiter.acquire();

    // V-001: Audit logging (AU-12)
    const startTime = Date.now();
    let success = false;
    let errorMessage: string | undefined;

    const url = new URL(`${CF_API_BASE}/graphql`);
    const body: { query: string; variables?: Record<string, unknown> } = { query };
    if (variables) {
      // V-006: Validate variables
      body.variables = validateGraphQLVariables(variables);
    }

    try {
      const response = await fetch(url.toString(), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.getToken()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      success = true;
      return result;
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : "Unknown error";
      throw error;
    } finally {
      logAuditEvent({
        timestamp: new Date().toISOString(),
        tool: "POST /graphql",
        parameters: { queryLength: query.length, hasVariables: !!variables },
        success,
        durationMs: Date.now() - startTime,
        ...(errorMessage && { errorMessage }),
      });
    }
  }

  // ============ ACCOUNT ROLES ============
  async listAccountRoles(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/roles`);
  }

  // ============ ACCOUNT RULESETS ============
  async listAccountRulesets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/rulesets`);
  }

  async getAccountRuleset(accountId: string, rulesetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/rulesets/${rulesetId}`);
  }

  // ============ ACCESS (Additional) ============
  async listAccessGroups(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/groups`);
  }

  async listAccessServiceTokens(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/service_tokens`);
  }

  // ============ WORKERS (Additional) ============
  async listWorkerServices(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workers/services`);
  }

  // ============ LOAD BALANCING (Additional) ============
  async listLoadBalancerMonitors(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/load_balancers/monitors`);
  }

  // ============ TRANSFORM RULES ============
  async getOriginRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_request_origin/entrypoint`);
  }

  async getUrlRewriteRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_request_transform/entrypoint`);
  }

  async getRequestHeaderRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_request_late_transform/entrypoint`);
  }

  async getResponseHeaderRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_response_headers_transform/entrypoint`);
  }

  // ============ CACHE RULES ============
  async getCacheRules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/http_request_cache_settings/entrypoint`);
  }

  // ============ DDOS ============
  async getDdosL7Rules(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rulesets/phases/ddos_l7/entrypoint`);
  }

  async getDdosL4Rules(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/rulesets/phases/ddos_l4/entrypoint`);
  }

  // ============ SPECTRUM ============
  async listSpectrumApps(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/spectrum/apps`);
  }

  // ============ API SHIELD ============
  async listApiShieldOperations(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/api_gateway/operations`);
  }

  async listApiShieldSchemas(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/api_gateway/schemas`);
  }

  async getApiShieldConfig(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/api_gateway/configuration`);
  }

  // ============ D1 DATABASES ============
  async listD1Databases(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/d1/database`);
  }

  async getD1Database(accountId: string, databaseId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/d1/database/${databaseId}`);
  }

  // ============ R2 STORAGE ============
  async listR2Buckets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/r2/buckets`);
  }

  // ============ KV NAMESPACES ============
  async listKVNamespaces(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/storage/kv/namespaces`);
  }

  async getKVNamespace(accountId: string, namespaceId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}`);
  }

  async listKVKeys(accountId: string, namespaceId: string, params?: { prefix?: string; limit?: number }) {
    return this.request<any[]>("GET", `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/keys`, params as Record<string, string | number | undefined>);
  }

  // ============ DURABLE OBJECTS ============
  async listDurableObjectNamespaces(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workers/durable_objects/namespaces`);
  }

  // ============ QUEUES ============
  async listQueues(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/queues`);
  }

  async getQueue(accountId: string, queueId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/queues/${queueId}`);
  }

  // ============ TUNNELS ============
  async listTunnels(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cfd_tunnel`);
  }

  async getTunnel(accountId: string, tunnelId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cfd_tunnel/${tunnelId}`);
  }

  async listTunnelConnections(accountId: string, tunnelId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cfd_tunnel/${tunnelId}/connections`);
  }

  // ============ LOGPUSH ============
  async listLogpushJobsZone(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/logpush/jobs`);
  }

  async listLogpushJobsAccount(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/logpush/jobs`);
  }

  // ============ EMAIL ROUTING ============
  async getEmailRoutingSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/email/routing`);
  }

  async listEmailRoutingRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/email/routing/rules`);
  }

  async listEmailRoutingAddresses(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email/routing/addresses`);
  }

  // ============ PAGES ============
  async listPagesProjects(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/pages/projects`);
  }

  async getPagesProject(accountId: string, projectName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/pages/projects/${projectName}`);
  }

  async listPagesDeployments(accountId: string, projectName: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/pages/projects/${projectName}/deployments`);
  }

  // ============ STREAM ============
  async listStreamVideos(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/stream`);
  }

  async getStreamVideo(accountId: string, videoId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/stream/${videoId}`);
  }

  // ============ IMAGES ============
  async listImages(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/images/v1`);
  }

  async getImagesStats(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/images/v1/stats`);
  }

  // ============ REGISTRAR ============
  async listRegistrarDomains(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/registrar/domains`);
  }

  async getRegistrarDomain(accountId: string, domainName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/registrar/domains/${domainName}`);
  }

  // ============ HEALTHCHECKS ============
  async listHealthchecks(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/healthchecks`);
  }

  async getHealthcheck(zoneId: string, healthcheckId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/healthchecks/${healthcheckId}`);
  }

  // ============ IP ACCESS RULES ============
  async listIPAccessRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/firewall/access_rules/rules`);
  }

  // ============ ZONE LOCKDOWN ============
  async listZoneLockdownRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/firewall/lockdowns`);
  }

  // ============ USER AGENT RULES ============
  async listUserAgentRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/firewall/ua_rules`);
  }

  // ============ ORIGIN CA ============
  async listOriginCACertificates(zoneId: string) {
    return this.request<any[]>("GET", `/certificates`, { zone_id: zoneId });
  }

  // ============ CLIENT CERTIFICATES (mTLS) ============
  async listClientCertificates(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/client_certificates`);
  }

  // ============ AUTHENTICATED ORIGIN PULLS ============
  async getAuthenticatedOriginPulls(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/origin_tls_client_auth/settings`);
  }

  // ============ FILTERS ============
  async listFilters(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/filters`);
  }

  // ============ SNIPPETS ============
  async listSnippets(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/snippets`);
  }

  // ============ WEB3 HOSTNAMES ============
  async listWeb3Hostnames(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/web3/hostnames`);
  }

  // ============ ZARAZ ============
  async getZarazConfig(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/zaraz/config`);
  }

  // ============ MISSING INDIVIDUAL GET ENDPOINTS ============
  async getZoneSetting(zoneId: string, settingName: string) {
    return this.request<any>("GET", `/zones/${zoneId}/settings/${settingName}`);
  }

  async getCertificatePack(zoneId: string, certificatePackId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/ssl/certificate_packs/${certificatePackId}`);
  }

  async getCustomCertificate(zoneId: string, certificateId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/custom_certificates/${certificateId}`);
  }

  async getLegacyRateLimit(zoneId: string, rateLimitId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/rate_limits/${rateLimitId}`);
  }

  async getDNSRecord(zoneId: string, dnsRecordId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/dns_records/${dnsRecordId}`);
  }

  async getPageRule(zoneId: string, pageruleId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/pagerules/${pageruleId}`);
  }

  async getWorkerScript(accountId: string, scriptName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/workers/scripts/${scriptName}`);
  }

  async getCustomHostname(zoneId: string, customHostnameId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/custom_hostnames/${customHostnameId}`);
  }

  async getWaitingRoom(zoneId: string, waitingRoomId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/waiting_rooms/${waitingRoomId}`);
  }

  // ============ WORKERS AI ============
  async listAIModels(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai/models/search`);
  }

  // ============ VECTORIZE ============
  async listVectorizeIndexes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/vectorize/indexes`);
  }

  async getVectorizeIndex(accountId: string, indexName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/vectorize/indexes/${indexName}`);
  }

  // ============ AI GATEWAY ============
  async listAIGateways(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-gateway/gateways`);
  }

  async getAIGatewayLogs(accountId: string, gatewayId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/logs`);
  }

  // ============ WORKERS SECRETS ============
  async listWorkerSecrets(accountId: string, scriptName: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workers/scripts/${scriptName}/secrets`);
  }

  // ============ WORKERS DEPLOYMENTS ============
  async listWorkerDeployments(accountId: string, scriptName: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workers/scripts/${scriptName}/deployments`);
  }

  // ============ WORKERS TAIL LOGS ============
  async listWorkerTails(accountId: string, scriptName: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workers/scripts/${scriptName}/tails`);
  }

  // ============ USER ============
  async getUser() {
    return this.request<any>("GET", `/user`);
  }

  async verifyToken() {
    return this.request<any>("GET", `/user/tokens/verify`);
  }

  // ============ BILLING ============
  async getBillingProfile(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/billing/profile`);
  }

  // ============ ZONE SUBSCRIPTION ============
  async getZoneSubscription(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/subscription`);
  }

  // ============ DEVICES (ZERO TRUST) ============
  async listDevices(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/devices`);
  }

  async listDevicePostureRules(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/devices/posture`);
  }

  async listDevicePolicies(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/devices/policies`);
  }

  // ============ DNSSEC ============
  async getDNSSEC(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/dnssec`);
  }

  // ============ PAGE SHIELD ============
  async getPageShieldSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/page_shield`);
  }

  async listPageShieldScripts(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/page_shield/scripts`);
  }

  async listPageShieldConnections(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/page_shield/connections`);
  }

  async listPageShieldPolicies(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/page_shield/policies`);
  }

  // ============ SECURITY CENTER ============
  async listSecurityInsights(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/security-center/insights`);
  }

  // ============ ALERTING/NOTIFICATIONS ============
  async listNotificationPolicies(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/alerting/v3/policies`);
  }

  async listNotificationHistory(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/alerting/v3/history`);
  }

  async listAvailableAlerts(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/alerting/v3/available_alerts`);
  }

  async listNotificationWebhooks(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/alerting/v3/destinations/webhooks`);
  }

  // ============ TUNNEL CONFIGURATIONS ============
  async getTunnelConfiguration(accountId: string, tunnelId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`);
  }

  // ============ TURNSTILE (CHALLENGES) ============
  async listTurnstileWidgets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/challenges/widgets`);
  }

  async getTurnstileWidget(accountId: string, widgetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/challenges/widgets/${widgetId}`);
  }

  // ============ GATEWAY (ZERO TRUST) ============
  async listGatewayRules(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/gateway/rules`);
  }

  async getGatewayConfiguration(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/gateway/configuration`);
  }

  async listGatewayLocations(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/gateway/locations`);
  }

  async listGatewayProxyEndpoints(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/gateway/proxy_endpoints`);
  }

  // ============ HYPERDRIVE ============
  async listHyperdriveConfigs(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/hyperdrive/configs`);
  }

  async getHyperdriveConfig(accountId: string, hyperdriveId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/hyperdrive/configs/${hyperdriveId}`);
  }

  // ============ URL NORMALIZATION ============
  async getUrlNormalization(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/url_normalization`);
  }

  // ============ MANAGED HEADERS ============
  async getManagedHeaders(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/managed_headers`);
  }

  // ============ KEYLESS SSL ============
  async listKeylessCertificates(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/keyless_certificates`);
  }

  // ============ MAGIC TRANSIT ============
  async listMagicTransitIpsecTunnels(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/magic/ipsec_tunnels`);
  }

  async getMagicTransitIpsecTunnel(accountId: string, tunnelId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/magic/ipsec_tunnels/${tunnelId}`);
  }

  async listMagicTransitGreTunnels(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/magic/gre_tunnels`);
  }

  async getMagicTransitGreTunnel(accountId: string, tunnelId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/magic/gre_tunnels/${tunnelId}`);
  }

  async listMagicTransitRoutes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/magic/routes`);
  }

  async getMagicTransitRoute(accountId: string, routeId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/magic/routes/${routeId}`);
  }

  async listMagicTransitConnectors(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/magic/connectors`);
  }

  async getMagicTransitConnector(accountId: string, connectorId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/magic/connectors/${connectorId}`);
  }

  async listMagicTransitSites(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/magic/sites`);
  }

  async getMagicTransitSite(accountId: string, siteId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/magic/sites/${siteId}`);
  }

  // ============ DNS FIREWALL ============
  async listDnsFirewallClusters(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dns_firewall`);
  }

  async getDnsFirewallCluster(accountId: string, clusterId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dns_firewall/${clusterId}`);
  }

  async getDnsFirewallAnalytics(accountId: string, clusterId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dns_firewall/${clusterId}/dns_analytics/report`);
  }

  // ============ SECONDARY DNS ============
  async getSecondaryDnsPrimary(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/secondary_dns/primaries`);
  }

  async listSecondaryDnsPeers(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/secondary_dns/peers`);
  }

  async getSecondaryDnsPeer(accountId: string, peerId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/secondary_dns/peers/${peerId}`);
  }

  async listSecondaryDnsTsigs(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/secondary_dns/tsigs`);
  }

  async getSecondaryDnsTsig(accountId: string, tsigId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/secondary_dns/tsigs/${tsigId}`);
  }

  async getSecondaryDnsIncoming(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/secondary_dns/incoming`);
  }

  async getSecondaryDnsOutgoing(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/secondary_dns/outgoing`);
  }

  async listSecondaryDnsAcls(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/secondary_dns/acls`);
  }

  async getSecondaryDnsAcl(accountId: string, aclId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/secondary_dns/acls/${aclId}`);
  }

  // ============ SPEED API ============
  async listSpeedTests(zoneId: string, url: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/speed_api/pages/${encodeURIComponent(url)}/tests`);
  }

  async getSpeedTest(zoneId: string, url: string, testId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/speed_api/pages/${encodeURIComponent(url)}/tests/${testId}`);
  }

  async getSpeedSchedule(zoneId: string, url: string) {
    return this.request<any>("GET", `/zones/${zoneId}/speed_api/schedule/${encodeURIComponent(url)}`);
  }

  async listSpeedAvailableRegions(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/speed_api/availabilities`);
  }

  async getSpeedPageTrend(zoneId: string, url: string) {
    return this.request<any>("GET", `/zones/${zoneId}/speed_api/pages/${encodeURIComponent(url)}/trend`);
  }

  // ============ CALLS (WebRTC) ============
  async listCallsApps(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/calls/apps`);
  }

  async getCallsApp(accountId: string, appId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/calls/apps/${appId}`);
  }

  async listCallsTurnKeys(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/calls/turn_keys`);
  }

  async getCallsTurnKey(accountId: string, keyId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/calls/turn_keys/${keyId}`);
  }

  // ============ DLP (Data Loss Prevention) ============
  async listDlpProfiles(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dlp/profiles`);
  }

  async getDlpProfile(accountId: string, profileId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dlp/profiles/${profileId}`);
  }

  async listDlpDatasets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dlp/datasets`);
  }

  async getDlpDataset(accountId: string, datasetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dlp/datasets/${datasetId}`);
  }

  async listDlpPatterns(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dlp/patterns`);
  }

  async getDlpPayloadLogSettings(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dlp/payload_log`);
  }

  // ============ CLOUDFLARE IPS ============
  async getCloudflareIps() {
    return this.request<any>("GET", `/ips`);
  }

  // ============ MEMBERSHIPS ============
  async listMemberships() {
    return this.request<any[]>("GET", `/memberships`);
  }

  async getMembership(membershipId: string) {
    return this.request<any>("GET", `/memberships/${membershipId}`);
  }

  // ============ ACCESS (EXTENDED) ============
  async listAccessBookmarks(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/bookmarks`);
  }

  async getAccessBookmark(accountId: string, bookmarkId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/bookmarks/${bookmarkId}`);
  }

  async listAccessCertificates(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/certificates`);
  }

  async getAccessCertificate(accountId: string, certificateId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/certificates/${certificateId}`);
  }

  async getAccessCertificateSettings(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/certificates/settings`);
  }

  async listAccessCustomPages(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/custom_pages`);
  }

  async getAccessCustomPage(accountId: string, customPageId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/custom_pages/${customPageId}`);
  }

  async listAccessIdentityProviders(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/identity_providers`);
  }

  async getAccessIdentityProvider(accountId: string, identityProviderId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/identity_providers/${identityProviderId}`);
  }

  async getAccessKeys(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/keys`);
  }

  async listAccessLogs(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/logs/access_requests`);
  }

  async getAccessOrganization(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/organizations`);
  }

  async listAccessTags(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/tags`);
  }

  async getAccessTag(accountId: string, tagName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/access/tags/${tagName}`);
  }

  async listAccessUsers(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/users`);
  }

  async listAccessUserActiveSessions(accountId: string, userId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/users/${userId}/active_sessions`);
  }

  async listAccessUserFailedLogins(accountId: string, userId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/access/users/${userId}/failed_logins`);
  }

  // ============ AI GATEWAY (EXTENDED) ============
  async listAiGatewayDatasets(accountId: string, gatewayId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/datasets`);
  }

  async getAiGatewayDataset(accountId: string, gatewayId: string, datasetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/datasets/${datasetId}`);
  }

  async listAiGatewayEvaluations(accountId: string, gatewayId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/evaluations`);
  }

  async getAiGatewayEvaluation(accountId: string, gatewayId: string, evaluationId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/evaluations/${evaluationId}`);
  }

  async listAiGatewayRoutes(accountId: string, gatewayId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/routes`);
  }

  async getAiGatewayRoute(accountId: string, gatewayId: string, routeId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/ai-gateway/gateways/${gatewayId}/routes/${routeId}`);
  }

  // ============ IP ADDRESSING (BYOIP) ============
  async listAddressMaps(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/addressing/address_maps`);
  }

  async getAddressMap(accountId: string, addressMapId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/addressing/address_maps/${addressMapId}`);
  }

  async listIpPrefixes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/addressing/prefixes`);
  }

  async getIpPrefix(accountId: string, prefixId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/addressing/prefixes/${prefixId}`);
  }

  async getIpPrefixBgpStatus(accountId: string, prefixId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/addressing/prefixes/${prefixId}/bgp/status`);
  }

  async listIpPrefixDelegations(accountId: string, prefixId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/addressing/prefixes/${prefixId}/delegations`);
  }

  async listAddressingServices(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/addressing/services`);
  }

  // ============ URL SCANNER ============
  async getUrlScan(accountId: string, scanId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/urlscanner/scan/${scanId}`);
  }

  async getUrlScanHar(accountId: string, scanId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/urlscanner/scan/${scanId}/har`);
  }

  // ============ AI SEARCH ============
  async listAiSearchInstances(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-search/instances`);
  }

  async getAiSearchInstance(accountId: string, instanceId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/ai-search/instances/${instanceId}`);
  }

  async listAiSearchItems(accountId: string, instanceId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-search/instances/${instanceId}/items`);
  }

  async listAiSearchJobs(accountId: string, instanceId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/ai-search/instances/${instanceId}/jobs`);
  }

  async getAiSearchJob(accountId: string, instanceId: string, jobId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/ai-search/instances/${instanceId}/jobs/${jobId}`);
  }

  // ============ WORKERS BUILDS ============
  async listWorkerBuilds(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/builds`);
  }

  async getWorkerBuild(accountId: string, buildId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/builds/${buildId}`);
  }

  // ============ WORKERS WORKFLOWS ============
  async listWorkflows(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workflows`);
  }

  async getWorkflow(accountId: string, workflowName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/workflows/${workflowName}`);
  }

  async listWorkflowInstances(accountId: string, workflowName: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/workflows/${workflowName}/instances`);
  }

  async getWorkflowInstance(accountId: string, workflowName: string, instanceId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/workflows/${workflowName}/instances/${instanceId}`);
  }

  // ============ CNI (INTERCONNECT) ============
  async listCniInterconnects(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cni/interconnects`);
  }

  async getCniInterconnect(accountId: string, interconnectId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cni/interconnects/${interconnectId}`);
  }

  async listCniSlots(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cni/slots`);
  }

  async getCniSettings(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cni/settings`);
  }

  // ============ R2 PIPELINES ============
  async listR2Pipelines(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/pipelines`);
  }

  async getR2Pipeline(accountId: string, pipelineName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/pipelines/${pipelineName}`);
  }

  // ============ IAM/PERMISSIONS ============
  async listPermissionGroups(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/iam/permission_groups`);
  }

  async getPermissionGroup(accountId: string, groupId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/iam/permission_groups/${groupId}`);
  }

  async listResourceGroups(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/iam/resource_groups`);
  }

  async getResourceGroup(accountId: string, groupId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/iam/resource_groups/${groupId}`);
  }

  // ============ ZERO TRUST RISK SCORING ============
  async listRiskScoringBehaviors(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/zt_risk_scoring/behaviors`);
  }

  async listRiskScoringIntegrations(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/zt_risk_scoring/integrations`);
  }

  async getRiskScoringIntegration(accountId: string, integrationId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/zt_risk_scoring/integrations/${integrationId}`);
  }

  // ============ R2 CATALOG ============
  async listR2Catalogs(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/r2-catalog/catalogs`);
  }

  async getR2Catalog(accountId: string, catalogName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/r2-catalog/catalogs/${catalogName}`);
  }

  // ============ TEAM NETWORK ROUTES ============
  async listTeamnetRoutes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/teamnet/routes`);
  }

  async listTeamnetVirtualNetworks(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/teamnet/virtual_networks`);
  }

  async getTeamnetVirtualNetwork(accountId: string, vnetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/teamnet/virtual_networks/${vnetId}`);
  }

  // ============ SECRETS STORE ============
  async listSecretsStores(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/secrets_store/stores`);
  }

  async getSecretsStore(accountId: string, storeId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/secrets_store/stores/${storeId}`);
  }

  async listSecretsStoreSecrets(accountId: string, storeId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/secrets_store/stores/${storeId}/secrets`);
  }

  // ============ PACKET CAPTURES ============
  async listPcaps(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/pcaps`);
  }

  async getPcap(accountId: string, pcapId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/pcaps/${pcapId}`);
  }

  async getPcapOwnership(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/pcaps/ownership`);
  }

  // ============ MAGIC NETWORK MONITORING ============
  async getMnmConfig(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/mnm/config`);
  }

  async listMnmRules(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/mnm/rules`);
  }

  async getMnmRule(accountId: string, ruleId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/mnm/rules/${ruleId}`);
  }

  // ============ WARP CONNECTOR ============
  async listWarpConnectors(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/warp_connector`);
  }

  async getWarpConnector(accountId: string, connectorId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/warp_connector/${connectorId}`);
  }

  // ============ MTLS CERTIFICATES (ACCOUNT) ============
  async listAccountMtlsCertificates(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/mtls_certificates`);
  }

  async getAccountMtlsCertificate(accountId: string, certificateId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/mtls_certificates/${certificateId}`);
  }

  // ============ ACCOUNT DNS SETTINGS ============
  async getAccountDnsSettings(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dns_settings`);
  }

  async listDnsViews(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dns_settings/views`);
  }

  async getDnsView(accountId: string, viewId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dns_settings/views/${viewId}`);
  }

  // ============ ZONE: API SCHEMA VALIDATION ============
  async getSchemaValidationSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/schema_validation/settings`);
  }

  async listApiSchemas(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/schema_validation/schemas`);
  }

  // ============ ZONE: TOKEN VALIDATION ============
  async getTokenValidationSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/token_validation/settings`);
  }

  // ============ ZONE: SMART SHIELD ============
  async getSmartShieldSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/smart_shield`);
  }

  // ============ ZONE: LOGS ============
  async getZoneLogsRetention(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/logs/control/retention/flag`);
  }

  // ============ ZONE: LEAKED CREDENTIAL CHECKS ============
  async getLeakedCredentialCheckSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/leaked-credential-checks`);
  }

  async listLeakedCredentialDetections(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/leaked-credential-checks/detections`);
  }

  // ============ ZONE: ADVANCED CERTIFICATE MANAGER ============
  async getTotalTlsSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/acm/total_tls`);
  }

  // ============ ZONE: DNS ANALYTICS ============
  async getDnsAnalyticsReport(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/dns_analytics/report`);
  }

  // ============ ZONE: FRAUD DETECTION ============
  async getFraudDetectionSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/fraud_detection`);
  }

  // ============ ZONE: CLOUD CONNECTOR ============
  async listCloudConnectorRules(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/cloud_connector/rules`);
  }

  // ============ ZONE: DCV DELEGATION ============
  async getDcvDelegation(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/dcv_delegation/uuid`);
  }

  // ============ INTEL ============
  async getIntelAsn(accountId: string, asn: number) {
    return this.request<any>("GET", `/accounts/${accountId}/intel/asn/${asn}`);
  }

  async getIntelDomain(accountId: string, domain?: string) {
    const params = domain ? `?domain=${encodeURIComponent(domain)}` : '';
    return this.request<any>("GET", `/accounts/${accountId}/intel/domain${params}`);
  }

  async getIntelDomainHistory(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/intel/domain-history`);
  }

  async getIntelIp(accountId: string, ipv4?: string, ipv6?: string) {
    const params = new URLSearchParams();
    if (ipv4) params.append('ipv4', ipv4);
    if (ipv6) params.append('ipv6', ipv6);
    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request<any>("GET", `/accounts/${accountId}/intel/ip${query}`);
  }

  async getIntelWhois(accountId: string, domain?: string) {
    const params = domain ? `?domain=${encodeURIComponent(domain)}` : '';
    return this.request<any>("GET", `/accounts/${accountId}/intel/whois${params}`);
  }

  async listIntelIndicatorFeeds(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/intel/indicator-feeds`);
  }

  async getIntelIndicatorFeed(accountId: string, feedId: number) {
    return this.request<any>("GET", `/accounts/${accountId}/intel/indicator-feeds/${feedId}`);
  }

  async listIntelSinkholes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/intel/sinkholes`);
  }

  async listIntelIpLists(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/intel/ip-lists`);
  }

  // ============ RULES/LISTS ============
  async listAccountRulesLists(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/rules/lists`);
  }

  async getAccountRulesList(accountId: string, listId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/rules/lists/${listId}`);
  }

  async listAccountRulesListItems(accountId: string, listId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/rules/lists/${listId}/items`);
  }

  // ============ API TOKENS ============
  async listAccountTokens(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/tokens`);
  }

  async getAccountToken(accountId: string, tokenId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/tokens/${tokenId}`);
  }

  async verifyAccountToken(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/tokens/verify`);
  }

  async listTokenPermissionGroups(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/tokens/permission_groups`);
  }

  // ============ RUM ============
  async listRumSites(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/rum/site_info/list`);
  }

  async getRumSite(accountId: string, siteId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/rum/site_info/${siteId}`);
  }

  // ============ ABUSE REPORTS ============
  async listAbuseReports(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/abuse-reports`);
  }

  async getAbuseReport(accountId: string, reportId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/abuse-reports/${reportId}`);
  }

  // ============ INFRASTRUCTURE TARGETS ============
  async listInfrastructureTargets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/infrastructure/targets`);
  }

  async getInfrastructureTarget(accountId: string, targetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/infrastructure/targets/${targetId}`);
  }

  // ============ CONNECTIVITY SERVICES ============
  async listConnectivityServices(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/connectivity/directory/services`);
  }

  async getConnectivityService(accountId: string, serviceId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/connectivity/directory/services/${serviceId}`);
  }

  // ============ DIAGNOSTICS ============
  async listEndpointHealthchecks(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/diagnostics/endpoint-healthchecks`);
  }

  async getEndpointHealthcheck(accountId: string, healthcheckId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/diagnostics/endpoint-healthchecks/${healthcheckId}`);
  }

  // ============ CONTAINERS ============
  async listContainers(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/containers`);
  }

  // ============ EVENT NOTIFICATIONS ============
  async getR2EventNotificationConfig(accountId: string, bucketName: string) {
    return this.request<any>("GET", `/accounts/${accountId}/event_notifications/r2/${bucketName}/configuration`);
  }

  // ============ ZONE: API GATEWAY ============
  async getApiGatewayConfig(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/api_gateway/configuration`);
  }

  async getApiGatewayDiscovery(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/api_gateway/discovery`);
  }

  async listApiGatewayOperations(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/api_gateway/operations`);
  }

  async getApiGatewayOperation(zoneId: string, operationId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/api_gateway/operations/${operationId}`);
  }

  async listApiGatewaySchemas(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/api_gateway/schemas`);
  }

  async listApiGatewayUserSchemas(zoneId: string) {
    return this.request<any[]>("GET", `/zones/${zoneId}/api_gateway/user_schemas`);
  }

  async getApiGatewayUserSchema(zoneId: string, schemaId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/api_gateway/user_schemas/${schemaId}`);
  }

  async getApiGatewaySettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/api_gateway/settings/schema_validation`);
  }

  // ============ ZONE: SPECTRUM (Analytics) ============
  async getSpectrumAnalyticsSummary(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/spectrum/analytics/events/summary`);
  }

  // ============ ZONE: CONTENT UPLOAD SCAN ============
  async getContentUploadScanSettings(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/content-upload-scan/settings`);
  }

  // ============ ZONE: HOLD ============
  async getZoneHold(zoneId: string) {
    return this.request<any>("GET", `/zones/${zoneId}/hold`);
  }

  // ============ SHARES (R2) ============
  async getR2Share(accountId: string, shareId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/shares/${shareId}`);
  }

  async listR2ShareRecipients(accountId: string, shareId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/shares/${shareId}/recipients`);
  }

  async listR2ShareResources(accountId: string, shareId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/shares/${shareId}/resources`);
  }

  // ============ SLURPER (MIGRATION) ============
  async listSlurperJobs(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/slurper/jobs`);
  }

  async getSlurperJob(accountId: string, jobId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/slurper/jobs/${jobId}`);
  }

  async getSlurperJobProgress(accountId: string, jobId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/slurper/jobs/${jobId}/progress`);
  }

  // ============ BOTNET FEED ============
  async getBotnetFeedAsnConfig(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/botnet_feed/configs/asn`);
  }

  async getBotnetFeedAsnReport(accountId: string, asnId: number) {
    return this.request<any>("GET", `/accounts/${accountId}/botnet_feed/asn/${asnId}/full_report`);
  }

  // ============ AUTORAG ============
  async listAutoragFiles(accountId: string, ragId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/autorag/rags/${ragId}/files`);
  }

  async listAutoragJobs(accountId: string, ragId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/autorag/rags/${ragId}/jobs`);
  }

  async getAutoragJob(accountId: string, ragId: string, jobId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/autorag/rags/${ragId}/jobs/${jobId}`);
  }

  // ============ DEX (Digital Experience) ============
  async listDexColos(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dex/colos`);
  }

  async listDexFleetStatusDevices(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dex/fleet-status/devices`);
  }

  async getDexFleetStatusLive(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/fleet-status/live`);
  }

  async getDexFleetStatusOverTime(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/fleet-status/over-time`);
  }

  async listDexTestsOverview(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dex/tests/overview`);
  }

  async getDexTestsUniqueDevices(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/tests/unique-devices`);
  }

  async getDexHttpTest(accountId: string, testId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/http-tests/${testId}`);
  }

  async getDexTracerouteTest(accountId: string, testId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/traceroute-tests/${testId}`);
  }

  async listDexRules(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dex/rules`);
  }

  async getDexRule(accountId: string, ruleId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/rules/${ruleId}`);
  }

  async listDexCommands(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/dex/commands`);
  }

  async getDexCommandsQuota(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/dex/commands/quota`);
  }

  // ============ BRAND PROTECTION ============
  async listBrandProtectionAlerts(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/alerts`);
  }

  async listBrandProtectionBrands(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/brands`);
  }

  async listBrandProtectionLogos(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/logos`);
  }

  async getBrandProtectionLogo(accountId: string, logoId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/brand-protection/logos/${logoId}`);
  }

  async listBrandProtectionMatches(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/matches`);
  }

  async listBrandProtectionLogoMatches(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/logo-matches`);
  }

  async listBrandProtectionQueries(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/queries`);
  }

  async getBrandProtectionUrlInfo(accountId: string, url?: string) {
    const params = url ? `?url=${encodeURIComponent(url)}` : '';
    return this.request<any>("GET", `/accounts/${accountId}/brand-protection/url-info${params}`);
  }

  async getBrandProtectionDomainInfo(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/brand-protection/domain-info`);
  }

  async listBrandProtectionTrackedDomains(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/tracked-domains`);
  }

  async listBrandProtectionRecentSubmissions(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/brand-protection/recent-submissions`);
  }

  // ============ EMAIL SECURITY ============
  async listEmailSecurityInvestigate(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/investigate`);
  }

  async getEmailSecurityMessage(accountId: string, postfixId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/email-security/investigate/${postfixId}`);
  }

  async getEmailSecurityMessageDetections(accountId: string, postfixId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/email-security/investigate/${postfixId}/detections`);
  }

  async listEmailSecuritySubmissions(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/submissions`);
  }

  async listEmailSecurityAllowPolicies(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/settings/allow_policies`);
  }

  async getEmailSecurityAllowPolicy(accountId: string, policyId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/email-security/settings/allow_policies/${policyId}`);
  }

  async listEmailSecurityBlockSenders(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/settings/block_senders`);
  }

  async getEmailSecurityBlockSender(accountId: string, patternId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/email-security/settings/block_senders/${patternId}`);
  }

  async listEmailSecurityDomains(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/settings/domains`);
  }

  async getEmailSecurityDomain(accountId: string, domainId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/email-security/settings/domains/${domainId}`);
  }

  async listEmailSecurityImpersonationRegistry(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/settings/impersonation_registry`);
  }

  async listEmailSecurityTrustedDomains(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/email-security/settings/trusted_domains`);
  }

  async getEmailSecurityPhishguardReports(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/email-security/phishguard/reports`);
  }

  // ============ REALTIME KIT ============
  async listRealtimeApps(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/apps`);
  }

  async getRealtimeAnalyticsDaywise(accountId: string, appId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/analytics/daywise`);
  }

  async listRealtimeLivestreams(accountId: string, appId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/livestreams`);
  }

  async getRealtimeLivestream(accountId: string, appId: string, livestreamId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/livestreams/${livestreamId}`);
  }

  async listRealtimeMeetings(accountId: string, appId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/meetings`);
  }

  async getRealtimeMeeting(accountId: string, appId: string, meetingId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/meetings/${meetingId}`);
  }

  async listRealtimeMeetingParticipants(accountId: string, appId: string, meetingId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/meetings/${meetingId}/participants`);
  }

  async listRealtimePresets(accountId: string, appId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/presets`);
  }

  async getRealtimePreset(accountId: string, appId: string, presetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/presets/${presetId}`);
  }

  async listRealtimeRecordings(accountId: string, appId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/recordings`);
  }

  async getRealtimeRecording(accountId: string, appId: string, recordingId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/recordings/${recordingId}`);
  }

  async listRealtimeSessions(accountId: string, appId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/sessions`);
  }

  async getRealtimeSession(accountId: string, appId: string, sessionId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/sessions/${sessionId}`);
  }

  async getRealtimeSessionSummary(accountId: string, appId: string, sessionId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/sessions/${sessionId}/summary`);
  }

  async getRealtimeSessionTranscript(accountId: string, appId: string, sessionId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/sessions/${sessionId}/transcript`);
  }

  async listRealtimeWebhooks(accountId: string, appId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/realtime/kit/${appId}/webhooks`);
  }

  async getRealtimeWebhook(accountId: string, appId: string, webhookId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/realtime/kit/${appId}/webhooks/${webhookId}`);
  }

  // ============ ZERO TRUST SETTINGS ============
  async getZerotrustConnectivitySettings(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/zerotrust/connectivity_settings`);
  }

  async listZerotrustHostnameRoutes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/zerotrust/routes/hostname`);
  }

  async getZerotrustHostnameRoute(accountId: string, hostnameRouteId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/zerotrust/routes/hostname/${hostnameRouteId}`);
  }

  async listZerotrustSubnets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/zerotrust/subnets`);
  }

  // ============ CLOUDFORCE ONE ============
  async listCloudforceOneEvents(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events`);
  }

  async getCloudforceOneEvent(accountId: string, eventId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/events/${eventId}`);
  }

  async getCloudforceOneEventsAggregate(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/events/aggregate`);
  }

  async listCloudforceOneCategories(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/categories`);
  }

  async listCloudforceOneCountries(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/countries`);
  }

  async listCloudforceOneDatasets(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/dataset`);
  }

  async getCloudforceOneDataset(accountId: string, datasetId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/events/dataset/${datasetId}`);
  }

  async listCloudforceOneIndicators(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/indicators`);
  }

  async listCloudforceOneIndicatorTypes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/indicator-types`);
  }

  async listCloudforceOneTags(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/tags`);
  }

  async listCloudforceOneTargetIndustries(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/targetIndustries`);
  }

  async listCloudforceOneQueries(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/events/queries`);
  }

  async getCloudforceOneQuery(accountId: string, queryId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/events/queries/${queryId}`);
  }

  async getCloudforceOneRequest(accountId: string, requestId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/requests/${requestId}`);
  }

  async getCloudforceOneRequestsQuota(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/requests/quota`);
  }

  async listCloudforceOneRequestTypes(accountId: string) {
    return this.request<any[]>("GET", `/accounts/${accountId}/cloudforce-one/requests/types`);
  }

  async getCloudforceOneScansConfig(accountId: string) {
    return this.request<any>("GET", `/accounts/${accountId}/cloudforce-one/scans/config`);
  }
}
