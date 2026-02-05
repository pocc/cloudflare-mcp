#!/usr/bin/env node
// Security: V-001 audit logging applied at API client level (AU-12)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { CloudflareClient } from "./api-client.js";
import { toolDefinitions } from "./tools.js";

// Get API token from environment
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
if (!apiToken) {
  console.error("Error: CLOUDFLARE_API_TOKEN environment variable is required");
  process.exit(1);
}

const client = new CloudflareClient({ apiToken });

// Create MCP server
const server = new McpServer({
  name: "cloudflare-api",
  version: "1.0.0",
});

// Register all tools
server.tool(
  toolDefinitions.list_accounts.name,
  toolDefinitions.list_accounts.description,
  toolDefinitions.list_accounts.inputSchema.shape,
  async () => {
    const result = await client.listAccounts();
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_account.name,
  toolDefinitions.get_account.description,
  toolDefinitions.get_account.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getAccount(account_id);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_account_members.name,
  toolDefinitions.list_account_members.description,
  toolDefinitions.list_account_members.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccountMembers(account_id);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_audit_logs.name,
  toolDefinitions.get_audit_logs.description,
  toolDefinitions.get_audit_logs.inputSchema.shape,
  async ({ account_id, since, before, actor_email, actor_ip, action_type, zone_name, per_page, page }) => {
    const result = await client.getAuditLogs(account_id, {
      since,
      before,
      actor_email,
      actor_ip,
      action_type,
      zone_name,
      per_page,
      page,
    });
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_zones.name,
  toolDefinitions.list_zones.description,
  toolDefinitions.list_zones.inputSchema.shape,
  async ({ account_id, name, status, per_page, page }) => {
    const result = await client.listZones({ account_id, name, status, per_page, page });
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zone.name,
  toolDefinitions.get_zone.description,
  toolDefinitions.get_zone.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getZone(zone_id);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zone_settings.name,
  toolDefinitions.get_zone_settings.description,
  toolDefinitions.get_zone_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getZoneSettings(zone_id);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ssl_settings.name,
  toolDefinitions.get_ssl_settings.description,
  toolDefinitions.get_ssl_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSSLSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_certificate_packs.name,
  toolDefinitions.list_certificate_packs.description,
  toolDefinitions.list_certificate_packs.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listCertificatePacks(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ssl_verification.name,
  toolDefinitions.get_ssl_verification.description,
  toolDefinitions.get_ssl_verification.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSSLVerification(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_custom_certificates.name,
  toolDefinitions.list_custom_certificates.description,
  toolDefinitions.list_custom_certificates.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listCustomCertificates(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_universal_ssl_settings.name,
  toolDefinitions.get_universal_ssl_settings.description,
  toolDefinitions.get_universal_ssl_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getUniversalSSLSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_rate_limiting_rules.name,
  toolDefinitions.get_rate_limiting_rules.description,
  toolDefinitions.get_rate_limiting_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getRateLimitingRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_legacy_rate_limits.name,
  toolDefinitions.list_legacy_rate_limits.description,
  toolDefinitions.list_legacy_rate_limits.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listLegacyRateLimits(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_zone_rulesets.name,
  toolDefinitions.list_zone_rulesets.description,
  toolDefinitions.list_zone_rulesets.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listZoneRulesets(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ruleset.name,
  toolDefinitions.get_ruleset.description,
  toolDefinitions.get_ruleset.inputSchema.shape,
  async ({ zone_id, ruleset_id }) => {
    const result = await client.getRuleset(zone_id, ruleset_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_waf_custom_rules.name,
  toolDefinitions.get_waf_custom_rules.description,
  toolDefinitions.get_waf_custom_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getWAFCustomRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_waf_managed_rules.name,
  toolDefinitions.get_waf_managed_rules.description,
  toolDefinitions.get_waf_managed_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getWAFManagedRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dns_records.name,
  toolDefinitions.list_dns_records.description,
  toolDefinitions.list_dns_records.inputSchema.shape,
  async ({ zone_id, type, name, per_page }) => {
    const result = await client.listDNSRecords(zone_id, { type, name, per_page });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_firewall_rules.name,
  toolDefinitions.list_firewall_rules.description,
  toolDefinitions.list_firewall_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listFirewallRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_page_rules.name,
  toolDefinitions.list_page_rules.description,
  toolDefinitions.list_page_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listPageRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_workers.name,
  toolDefinitions.list_workers.description,
  toolDefinitions.list_workers.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listWorkers(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_worker_routes.name,
  toolDefinitions.list_worker_routes.description,
  toolDefinitions.list_worker_routes.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listWorkerRoutes(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_load_balancers.name,
  toolDefinitions.list_load_balancers.description,
  toolDefinitions.list_load_balancers.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listLoadBalancers(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_origin_pools.name,
  toolDefinitions.list_origin_pools.description,
  toolDefinitions.list_origin_pools.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listOriginPools(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_custom_hostnames.name,
  toolDefinitions.list_custom_hostnames.description,
  toolDefinitions.list_custom_hostnames.inputSchema.shape,
  async ({ zone_id, hostname, per_page }) => {
    const result = await client.listCustomHostnames(zone_id, { hostname, per_page });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_apps.name,
  toolDefinitions.list_access_apps.description,
  toolDefinitions.list_access_apps.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessApps(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_policies.name,
  toolDefinitions.list_access_policies.description,
  toolDefinitions.list_access_policies.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessPolicies(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_bot_management.name,
  toolDefinitions.get_bot_management.description,
  toolDefinitions.get_bot_management.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getBotManagement(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_argo_settings.name,
  toolDefinitions.get_argo_settings.description,
  toolDefinitions.get_argo_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getArgoSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_waiting_rooms.name,
  toolDefinitions.list_waiting_rooms.description,
  toolDefinitions.list_waiting_rooms.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listWaitingRooms(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cache_settings.name,
  toolDefinitions.get_cache_settings.description,
  toolDefinitions.get_cache_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getCacheSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zone_analytics.name,
  toolDefinitions.get_zone_analytics.description,
  toolDefinitions.get_zone_analytics.inputSchema.shape,
  async ({ zone_id, since, until }) => {
    const result = await client.getZoneAnalytics(zone_id, { since, until });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_analytics_by_colo.name,
  toolDefinitions.get_analytics_by_colo.description,
  toolDefinitions.get_analytics_by_colo.inputSchema.shape,
  async ({ zone_id, since, until }) => {
    const result = await client.getAnalyticsByColo(zone_id, { since, until });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.graphql_analytics.name,
  toolDefinitions.graphql_analytics.description,
  toolDefinitions.graphql_analytics.inputSchema.shape,
  async ({ query, variables }) => {
    const result = await client.graphqlAnalytics(query, variables);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_account_roles.name,
  toolDefinitions.list_account_roles.description,
  toolDefinitions.list_account_roles.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccountRoles(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_account_rulesets.name,
  toolDefinitions.list_account_rulesets.description,
  toolDefinitions.list_account_rulesets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccountRulesets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_account_ruleset.name,
  toolDefinitions.get_account_ruleset.description,
  toolDefinitions.get_account_ruleset.inputSchema.shape,
  async ({ account_id, ruleset_id }) => {
    const result = await client.getAccountRuleset(account_id, ruleset_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_groups.name,
  toolDefinitions.list_access_groups.description,
  toolDefinitions.list_access_groups.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessGroups(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_service_tokens.name,
  toolDefinitions.list_access_service_tokens.description,
  toolDefinitions.list_access_service_tokens.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessServiceTokens(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_worker_services.name,
  toolDefinitions.list_worker_services.description,
  toolDefinitions.list_worker_services.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listWorkerServices(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_load_balancer_monitors.name,
  toolDefinitions.list_load_balancer_monitors.description,
  toolDefinitions.list_load_balancer_monitors.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listLoadBalancerMonitors(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_origin_rules.name,
  toolDefinitions.get_origin_rules.description,
  toolDefinitions.get_origin_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getOriginRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_url_rewrite_rules.name,
  toolDefinitions.get_url_rewrite_rules.description,
  toolDefinitions.get_url_rewrite_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getUrlRewriteRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_request_header_rules.name,
  toolDefinitions.get_request_header_rules.description,
  toolDefinitions.get_request_header_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getRequestHeaderRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_response_header_rules.name,
  toolDefinitions.get_response_header_rules.description,
  toolDefinitions.get_response_header_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getResponseHeaderRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cache_rules.name,
  toolDefinitions.get_cache_rules.description,
  toolDefinitions.get_cache_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getCacheRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ddos_l7_rules.name,
  toolDefinitions.get_ddos_l7_rules.description,
  toolDefinitions.get_ddos_l7_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getDdosL7Rules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ddos_l4_rules.name,
  toolDefinitions.get_ddos_l4_rules.description,
  toolDefinitions.get_ddos_l4_rules.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getDdosL4Rules(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_spectrum_apps.name,
  toolDefinitions.list_spectrum_apps.description,
  toolDefinitions.list_spectrum_apps.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listSpectrumApps(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_api_shield_operations.name,
  toolDefinitions.list_api_shield_operations.description,
  toolDefinitions.list_api_shield_operations.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listApiShieldOperations(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_api_shield_schemas.name,
  toolDefinitions.list_api_shield_schemas.description,
  toolDefinitions.list_api_shield_schemas.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listApiShieldSchemas(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_api_shield_config.name,
  toolDefinitions.get_api_shield_config.description,
  toolDefinitions.get_api_shield_config.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getApiShieldConfig(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_d1_databases.name,
  toolDefinitions.list_d1_databases.description,
  toolDefinitions.list_d1_databases.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listD1Databases(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_d1_database.name,
  toolDefinitions.get_d1_database.description,
  toolDefinitions.get_d1_database.inputSchema.shape,
  async ({ account_id, database_id }) => {
    const result = await client.getD1Database(account_id, database_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_r2_buckets.name,
  toolDefinitions.list_r2_buckets.description,
  toolDefinitions.list_r2_buckets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listR2Buckets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_kv_namespaces.name,
  toolDefinitions.list_kv_namespaces.description,
  toolDefinitions.list_kv_namespaces.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listKVNamespaces(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_kv_namespace.name,
  toolDefinitions.get_kv_namespace.description,
  toolDefinitions.get_kv_namespace.inputSchema.shape,
  async ({ account_id, namespace_id }) => {
    const result = await client.getKVNamespace(account_id, namespace_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_kv_keys.name,
  toolDefinitions.list_kv_keys.description,
  toolDefinitions.list_kv_keys.inputSchema.shape,
  async ({ account_id, namespace_id, prefix, limit }) => {
    const result = await client.listKVKeys(account_id, namespace_id, { prefix, limit });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_durable_object_namespaces.name,
  toolDefinitions.list_durable_object_namespaces.description,
  toolDefinitions.list_durable_object_namespaces.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDurableObjectNamespaces(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_queues.name,
  toolDefinitions.list_queues.description,
  toolDefinitions.list_queues.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listQueues(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_queue.name,
  toolDefinitions.get_queue.description,
  toolDefinitions.get_queue.inputSchema.shape,
  async ({ account_id, queue_id }) => {
    const result = await client.getQueue(account_id, queue_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_tunnels.name,
  toolDefinitions.list_tunnels.description,
  toolDefinitions.list_tunnels.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listTunnels(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_tunnel.name,
  toolDefinitions.get_tunnel.description,
  toolDefinitions.get_tunnel.inputSchema.shape,
  async ({ account_id, tunnel_id }) => {
    const result = await client.getTunnel(account_id, tunnel_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_tunnel_connections.name,
  toolDefinitions.list_tunnel_connections.description,
  toolDefinitions.list_tunnel_connections.inputSchema.shape,
  async ({ account_id, tunnel_id }) => {
    const result = await client.listTunnelConnections(account_id, tunnel_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_logpush_jobs_zone.name,
  toolDefinitions.list_logpush_jobs_zone.description,
  toolDefinitions.list_logpush_jobs_zone.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listLogpushJobsZone(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_logpush_jobs_account.name,
  toolDefinitions.list_logpush_jobs_account.description,
  toolDefinitions.list_logpush_jobs_account.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listLogpushJobsAccount(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_routing_settings.name,
  toolDefinitions.get_email_routing_settings.description,
  toolDefinitions.get_email_routing_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getEmailRoutingSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_routing_rules.name,
  toolDefinitions.list_email_routing_rules.description,
  toolDefinitions.list_email_routing_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listEmailRoutingRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_routing_addresses.name,
  toolDefinitions.list_email_routing_addresses.description,
  toolDefinitions.list_email_routing_addresses.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailRoutingAddresses(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_pages_projects.name,
  toolDefinitions.list_pages_projects.description,
  toolDefinitions.list_pages_projects.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listPagesProjects(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_pages_project.name,
  toolDefinitions.get_pages_project.description,
  toolDefinitions.get_pages_project.inputSchema.shape,
  async ({ account_id, project_name }) => {
    const result = await client.getPagesProject(account_id, project_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_pages_deployments.name,
  toolDefinitions.list_pages_deployments.description,
  toolDefinitions.list_pages_deployments.inputSchema.shape,
  async ({ account_id, project_name }) => {
    const result = await client.listPagesDeployments(account_id, project_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_stream_videos.name,
  toolDefinitions.list_stream_videos.description,
  toolDefinitions.list_stream_videos.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listStreamVideos(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_stream_video.name,
  toolDefinitions.get_stream_video.description,
  toolDefinitions.get_stream_video.inputSchema.shape,
  async ({ account_id, video_id }) => {
    const result = await client.getStreamVideo(account_id, video_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_images.name,
  toolDefinitions.list_images.description,
  toolDefinitions.list_images.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listImages(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_images_stats.name,
  toolDefinitions.get_images_stats.description,
  toolDefinitions.get_images_stats.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getImagesStats(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_registrar_domains.name,
  toolDefinitions.list_registrar_domains.description,
  toolDefinitions.list_registrar_domains.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listRegistrarDomains(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_registrar_domain.name,
  toolDefinitions.get_registrar_domain.description,
  toolDefinitions.get_registrar_domain.inputSchema.shape,
  async ({ account_id, domain_name }) => {
    const result = await client.getRegistrarDomain(account_id, domain_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_healthchecks.name,
  toolDefinitions.list_healthchecks.description,
  toolDefinitions.list_healthchecks.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listHealthchecks(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_healthcheck.name,
  toolDefinitions.get_healthcheck.description,
  toolDefinitions.get_healthcheck.inputSchema.shape,
  async ({ zone_id, healthcheck_id }) => {
    const result = await client.getHealthcheck(zone_id, healthcheck_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ip_access_rules.name,
  toolDefinitions.list_ip_access_rules.description,
  toolDefinitions.list_ip_access_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listIPAccessRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_zone_lockdown_rules.name,
  toolDefinitions.list_zone_lockdown_rules.description,
  toolDefinitions.list_zone_lockdown_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listZoneLockdownRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_user_agent_rules.name,
  toolDefinitions.list_user_agent_rules.description,
  toolDefinitions.list_user_agent_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listUserAgentRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_origin_ca_certificates.name,
  toolDefinitions.list_origin_ca_certificates.description,
  toolDefinitions.list_origin_ca_certificates.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listOriginCACertificates(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_client_certificates.name,
  toolDefinitions.list_client_certificates.description,
  toolDefinitions.list_client_certificates.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listClientCertificates(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_authenticated_origin_pulls.name,
  toolDefinitions.get_authenticated_origin_pulls.description,
  toolDefinitions.get_authenticated_origin_pulls.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getAuthenticatedOriginPulls(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_filters.name,
  toolDefinitions.list_filters.description,
  toolDefinitions.list_filters.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listFilters(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_snippets.name,
  toolDefinitions.list_snippets.description,
  toolDefinitions.list_snippets.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listSnippets(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_web3_hostnames.name,
  toolDefinitions.list_web3_hostnames.description,
  toolDefinitions.list_web3_hostnames.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listWeb3Hostnames(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zaraz_config.name,
  toolDefinitions.get_zaraz_config.description,
  toolDefinitions.get_zaraz_config.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getZarazConfig(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zone_setting.name,
  toolDefinitions.get_zone_setting.description,
  toolDefinitions.get_zone_setting.inputSchema.shape,
  async ({ zone_id, setting_name }) => {
    const result = await client.getZoneSetting(zone_id, setting_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_certificate_pack.name,
  toolDefinitions.get_certificate_pack.description,
  toolDefinitions.get_certificate_pack.inputSchema.shape,
  async ({ zone_id, certificate_pack_id }) => {
    const result = await client.getCertificatePack(zone_id, certificate_pack_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_custom_certificate.name,
  toolDefinitions.get_custom_certificate.description,
  toolDefinitions.get_custom_certificate.inputSchema.shape,
  async ({ zone_id, certificate_id }) => {
    const result = await client.getCustomCertificate(zone_id, certificate_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_legacy_rate_limit.name,
  toolDefinitions.get_legacy_rate_limit.description,
  toolDefinitions.get_legacy_rate_limit.inputSchema.shape,
  async ({ zone_id, rate_limit_id }) => {
    const result = await client.getLegacyRateLimit(zone_id, rate_limit_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dns_record.name,
  toolDefinitions.get_dns_record.description,
  toolDefinitions.get_dns_record.inputSchema.shape,
  async ({ zone_id, dns_record_id }) => {
    const result = await client.getDNSRecord(zone_id, dns_record_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_page_rule.name,
  toolDefinitions.get_page_rule.description,
  toolDefinitions.get_page_rule.inputSchema.shape,
  async ({ zone_id, pagerule_id }) => {
    const result = await client.getPageRule(zone_id, pagerule_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_worker_script.name,
  toolDefinitions.get_worker_script.description,
  toolDefinitions.get_worker_script.inputSchema.shape,
  async ({ account_id, script_name }) => {
    const result = await client.getWorkerScript(account_id, script_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_custom_hostname.name,
  toolDefinitions.get_custom_hostname.description,
  toolDefinitions.get_custom_hostname.inputSchema.shape,
  async ({ zone_id, custom_hostname_id }) => {
    const result = await client.getCustomHostname(zone_id, custom_hostname_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_waiting_room.name,
  toolDefinitions.get_waiting_room.description,
  toolDefinitions.get_waiting_room.inputSchema.shape,
  async ({ zone_id, waiting_room_id }) => {
    const result = await client.getWaitingRoom(zone_id, waiting_room_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ai_models.name,
  toolDefinitions.list_ai_models.description,
  toolDefinitions.list_ai_models.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAIModels(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_vectorize_indexes.name,
  toolDefinitions.list_vectorize_indexes.description,
  toolDefinitions.list_vectorize_indexes.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listVectorizeIndexes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_vectorize_index.name,
  toolDefinitions.get_vectorize_index.description,
  toolDefinitions.get_vectorize_index.inputSchema.shape,
  async ({ account_id, index_name }) => {
    const result = await client.getVectorizeIndex(account_id, index_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ai_gateways.name,
  toolDefinitions.list_ai_gateways.description,
  toolDefinitions.list_ai_gateways.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAIGateways(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ai_gateway_logs.name,
  toolDefinitions.get_ai_gateway_logs.description,
  toolDefinitions.get_ai_gateway_logs.inputSchema.shape,
  async ({ account_id, gateway_id }) => {
    const result = await client.getAIGatewayLogs(account_id, gateway_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_worker_secrets.name,
  toolDefinitions.list_worker_secrets.description,
  toolDefinitions.list_worker_secrets.inputSchema.shape,
  async ({ account_id, script_name }) => {
    const result = await client.listWorkerSecrets(account_id, script_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_worker_deployments.name,
  toolDefinitions.list_worker_deployments.description,
  toolDefinitions.list_worker_deployments.inputSchema.shape,
  async ({ account_id, script_name }) => {
    const result = await client.listWorkerDeployments(account_id, script_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_worker_tails.name,
  toolDefinitions.list_worker_tails.description,
  toolDefinitions.list_worker_tails.inputSchema.shape,
  async ({ account_id, script_name }) => {
    const result = await client.listWorkerTails(account_id, script_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_user.name,
  toolDefinitions.get_user.description,
  toolDefinitions.get_user.inputSchema.shape,
  async () => {
    const result = await client.getUser();
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.verify_token.name,
  toolDefinitions.verify_token.description,
  toolDefinitions.verify_token.inputSchema.shape,
  async () => {
    const result = await client.verifyToken();
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_billing_profile.name,
  toolDefinitions.get_billing_profile.description,
  toolDefinitions.get_billing_profile.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getBillingProfile(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zone_subscription.name,
  toolDefinitions.get_zone_subscription.description,
  toolDefinitions.get_zone_subscription.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getZoneSubscription(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_devices.name,
  toolDefinitions.list_devices.description,
  toolDefinitions.list_devices.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDevices(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_device_posture_rules.name,
  toolDefinitions.list_device_posture_rules.description,
  toolDefinitions.list_device_posture_rules.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDevicePostureRules(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_device_policies.name,
  toolDefinitions.list_device_policies.description,
  toolDefinitions.list_device_policies.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDevicePolicies(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dnssec.name,
  toolDefinitions.get_dnssec.description,
  toolDefinitions.get_dnssec.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getDNSSEC(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_page_shield_settings.name,
  toolDefinitions.get_page_shield_settings.description,
  toolDefinitions.get_page_shield_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getPageShieldSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_page_shield_scripts.name,
  toolDefinitions.list_page_shield_scripts.description,
  toolDefinitions.list_page_shield_scripts.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listPageShieldScripts(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_page_shield_connections.name,
  toolDefinitions.list_page_shield_connections.description,
  toolDefinitions.list_page_shield_connections.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listPageShieldConnections(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_page_shield_policies.name,
  toolDefinitions.list_page_shield_policies.description,
  toolDefinitions.list_page_shield_policies.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listPageShieldPolicies(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_security_insights.name,
  toolDefinitions.list_security_insights.description,
  toolDefinitions.list_security_insights.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listSecurityInsights(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_notification_policies.name,
  toolDefinitions.list_notification_policies.description,
  toolDefinitions.list_notification_policies.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listNotificationPolicies(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_notification_history.name,
  toolDefinitions.list_notification_history.description,
  toolDefinitions.list_notification_history.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listNotificationHistory(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_available_alerts.name,
  toolDefinitions.list_available_alerts.description,
  toolDefinitions.list_available_alerts.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAvailableAlerts(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_notification_webhooks.name,
  toolDefinitions.list_notification_webhooks.description,
  toolDefinitions.list_notification_webhooks.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listNotificationWebhooks(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_tunnel_configuration.name,
  toolDefinitions.get_tunnel_configuration.description,
  toolDefinitions.get_tunnel_configuration.inputSchema.shape,
  async ({ account_id, tunnel_id }) => {
    const result = await client.getTunnelConfiguration(account_id, tunnel_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_turnstile_widgets.name,
  toolDefinitions.list_turnstile_widgets.description,
  toolDefinitions.list_turnstile_widgets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listTurnstileWidgets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_turnstile_widget.name,
  toolDefinitions.get_turnstile_widget.description,
  toolDefinitions.get_turnstile_widget.inputSchema.shape,
  async ({ account_id, widget_id }) => {
    const result = await client.getTurnstileWidget(account_id, widget_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_gateway_rules.name,
  toolDefinitions.list_gateway_rules.description,
  toolDefinitions.list_gateway_rules.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listGatewayRules(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_gateway_configuration.name,
  toolDefinitions.get_gateway_configuration.description,
  toolDefinitions.get_gateway_configuration.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getGatewayConfiguration(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_gateway_locations.name,
  toolDefinitions.list_gateway_locations.description,
  toolDefinitions.list_gateway_locations.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listGatewayLocations(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_gateway_proxy_endpoints.name,
  toolDefinitions.list_gateway_proxy_endpoints.description,
  toolDefinitions.list_gateway_proxy_endpoints.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listGatewayProxyEndpoints(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_hyperdrive_configs.name,
  toolDefinitions.list_hyperdrive_configs.description,
  toolDefinitions.list_hyperdrive_configs.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listHyperdriveConfigs(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_hyperdrive_config.name,
  toolDefinitions.get_hyperdrive_config.description,
  toolDefinitions.get_hyperdrive_config.inputSchema.shape,
  async ({ account_id, hyperdrive_id }) => {
    const result = await client.getHyperdriveConfig(account_id, hyperdrive_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_url_normalization.name,
  toolDefinitions.get_url_normalization.description,
  toolDefinitions.get_url_normalization.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getUrlNormalization(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_managed_headers.name,
  toolDefinitions.get_managed_headers.description,
  toolDefinitions.get_managed_headers.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getManagedHeaders(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_keyless_certificates.name,
  toolDefinitions.list_keyless_certificates.description,
  toolDefinitions.list_keyless_certificates.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listKeylessCertificates(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ MAGIC TRANSIT ============
server.tool(
  toolDefinitions.list_magic_transit_ipsec_tunnels.name,
  toolDefinitions.list_magic_transit_ipsec_tunnels.description,
  toolDefinitions.list_magic_transit_ipsec_tunnels.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listMagicTransitIpsecTunnels(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_magic_transit_ipsec_tunnel.name,
  toolDefinitions.get_magic_transit_ipsec_tunnel.description,
  toolDefinitions.get_magic_transit_ipsec_tunnel.inputSchema.shape,
  async ({ account_id, tunnel_id }) => {
    const result = await client.getMagicTransitIpsecTunnel(account_id, tunnel_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_magic_transit_gre_tunnels.name,
  toolDefinitions.list_magic_transit_gre_tunnels.description,
  toolDefinitions.list_magic_transit_gre_tunnels.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listMagicTransitGreTunnels(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_magic_transit_gre_tunnel.name,
  toolDefinitions.get_magic_transit_gre_tunnel.description,
  toolDefinitions.get_magic_transit_gre_tunnel.inputSchema.shape,
  async ({ account_id, tunnel_id }) => {
    const result = await client.getMagicTransitGreTunnel(account_id, tunnel_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_magic_transit_routes.name,
  toolDefinitions.list_magic_transit_routes.description,
  toolDefinitions.list_magic_transit_routes.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listMagicTransitRoutes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_magic_transit_route.name,
  toolDefinitions.get_magic_transit_route.description,
  toolDefinitions.get_magic_transit_route.inputSchema.shape,
  async ({ account_id, route_id }) => {
    const result = await client.getMagicTransitRoute(account_id, route_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_magic_transit_connectors.name,
  toolDefinitions.list_magic_transit_connectors.description,
  toolDefinitions.list_magic_transit_connectors.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listMagicTransitConnectors(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_magic_transit_connector.name,
  toolDefinitions.get_magic_transit_connector.description,
  toolDefinitions.get_magic_transit_connector.inputSchema.shape,
  async ({ account_id, connector_id }) => {
    const result = await client.getMagicTransitConnector(account_id, connector_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_magic_transit_sites.name,
  toolDefinitions.list_magic_transit_sites.description,
  toolDefinitions.list_magic_transit_sites.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listMagicTransitSites(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_magic_transit_site.name,
  toolDefinitions.get_magic_transit_site.description,
  toolDefinitions.get_magic_transit_site.inputSchema.shape,
  async ({ account_id, site_id }) => {
    const result = await client.getMagicTransitSite(account_id, site_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ DNS FIREWALL ============
server.tool(
  toolDefinitions.list_dns_firewall_clusters.name,
  toolDefinitions.list_dns_firewall_clusters.description,
  toolDefinitions.list_dns_firewall_clusters.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDnsFirewallClusters(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dns_firewall_cluster.name,
  toolDefinitions.get_dns_firewall_cluster.description,
  toolDefinitions.get_dns_firewall_cluster.inputSchema.shape,
  async ({ account_id, cluster_id }) => {
    const result = await client.getDnsFirewallCluster(account_id, cluster_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dns_firewall_analytics.name,
  toolDefinitions.get_dns_firewall_analytics.description,
  toolDefinitions.get_dns_firewall_analytics.inputSchema.shape,
  async ({ account_id, cluster_id }) => {
    const result = await client.getDnsFirewallAnalytics(account_id, cluster_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ SECONDARY DNS ============
server.tool(
  toolDefinitions.get_secondary_dns_primary.name,
  toolDefinitions.get_secondary_dns_primary.description,
  toolDefinitions.get_secondary_dns_primary.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSecondaryDnsPrimary(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_secondary_dns_peers.name,
  toolDefinitions.list_secondary_dns_peers.description,
  toolDefinitions.list_secondary_dns_peers.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listSecondaryDnsPeers(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_secondary_dns_peer.name,
  toolDefinitions.get_secondary_dns_peer.description,
  toolDefinitions.get_secondary_dns_peer.inputSchema.shape,
  async ({ account_id, peer_id }) => {
    const result = await client.getSecondaryDnsPeer(account_id, peer_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_secondary_dns_tsigs.name,
  toolDefinitions.list_secondary_dns_tsigs.description,
  toolDefinitions.list_secondary_dns_tsigs.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listSecondaryDnsTsigs(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_secondary_dns_tsig.name,
  toolDefinitions.get_secondary_dns_tsig.description,
  toolDefinitions.get_secondary_dns_tsig.inputSchema.shape,
  async ({ account_id, tsig_id }) => {
    const result = await client.getSecondaryDnsTsig(account_id, tsig_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_secondary_dns_incoming.name,
  toolDefinitions.get_secondary_dns_incoming.description,
  toolDefinitions.get_secondary_dns_incoming.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSecondaryDnsIncoming(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_secondary_dns_outgoing.name,
  toolDefinitions.get_secondary_dns_outgoing.description,
  toolDefinitions.get_secondary_dns_outgoing.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSecondaryDnsOutgoing(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_secondary_dns_acls.name,
  toolDefinitions.list_secondary_dns_acls.description,
  toolDefinitions.list_secondary_dns_acls.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listSecondaryDnsAcls(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_secondary_dns_acl.name,
  toolDefinitions.get_secondary_dns_acl.description,
  toolDefinitions.get_secondary_dns_acl.inputSchema.shape,
  async ({ account_id, acl_id }) => {
    const result = await client.getSecondaryDnsAcl(account_id, acl_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ SPEED API ============
server.tool(
  toolDefinitions.list_speed_tests.name,
  toolDefinitions.list_speed_tests.description,
  toolDefinitions.list_speed_tests.inputSchema.shape,
  async ({ zone_id, url }) => {
    const result = await client.listSpeedTests(zone_id, url);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_speed_test.name,
  toolDefinitions.get_speed_test.description,
  toolDefinitions.get_speed_test.inputSchema.shape,
  async ({ zone_id, url, test_id }) => {
    const result = await client.getSpeedTest(zone_id, url, test_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_speed_schedule.name,
  toolDefinitions.get_speed_schedule.description,
  toolDefinitions.get_speed_schedule.inputSchema.shape,
  async ({ zone_id, url }) => {
    const result = await client.getSpeedSchedule(zone_id, url);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_speed_available_regions.name,
  toolDefinitions.list_speed_available_regions.description,
  toolDefinitions.list_speed_available_regions.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listSpeedAvailableRegions(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_speed_page_trend.name,
  toolDefinitions.get_speed_page_trend.description,
  toolDefinitions.get_speed_page_trend.inputSchema.shape,
  async ({ zone_id, url }) => {
    const result = await client.getSpeedPageTrend(zone_id, url);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ CALLS (WebRTC) ============
server.tool(
  toolDefinitions.list_calls_apps.name,
  toolDefinitions.list_calls_apps.description,
  toolDefinitions.list_calls_apps.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCallsApps(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_calls_app.name,
  toolDefinitions.get_calls_app.description,
  toolDefinitions.get_calls_app.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.getCallsApp(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_calls_turn_keys.name,
  toolDefinitions.list_calls_turn_keys.description,
  toolDefinitions.list_calls_turn_keys.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCallsTurnKeys(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_calls_turn_key.name,
  toolDefinitions.get_calls_turn_key.description,
  toolDefinitions.get_calls_turn_key.inputSchema.shape,
  async ({ account_id, key_id }) => {
    const result = await client.getCallsTurnKey(account_id, key_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ DLP (Data Loss Prevention) ============
server.tool(
  toolDefinitions.list_dlp_profiles.name,
  toolDefinitions.list_dlp_profiles.description,
  toolDefinitions.list_dlp_profiles.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDlpProfiles(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dlp_profile.name,
  toolDefinitions.get_dlp_profile.description,
  toolDefinitions.get_dlp_profile.inputSchema.shape,
  async ({ account_id, profile_id }) => {
    const result = await client.getDlpProfile(account_id, profile_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dlp_datasets.name,
  toolDefinitions.list_dlp_datasets.description,
  toolDefinitions.list_dlp_datasets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDlpDatasets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dlp_dataset.name,
  toolDefinitions.get_dlp_dataset.description,
  toolDefinitions.get_dlp_dataset.inputSchema.shape,
  async ({ account_id, dataset_id }) => {
    const result = await client.getDlpDataset(account_id, dataset_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dlp_patterns.name,
  toolDefinitions.list_dlp_patterns.description,
  toolDefinitions.list_dlp_patterns.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDlpPatterns(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dlp_payload_log_settings.name,
  toolDefinitions.get_dlp_payload_log_settings.description,
  toolDefinitions.get_dlp_payload_log_settings.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getDlpPayloadLogSettings(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ CLOUDFLARE IPS ============
server.tool(
  toolDefinitions.get_cloudflare_ips.name,
  toolDefinitions.get_cloudflare_ips.description,
  toolDefinitions.get_cloudflare_ips.inputSchema.shape,
  async () => {
    const result = await client.getCloudflareIps();
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ MEMBERSHIPS ============
server.tool(
  toolDefinitions.list_memberships.name,
  toolDefinitions.list_memberships.description,
  toolDefinitions.list_memberships.inputSchema.shape,
  async () => {
    const result = await client.listMemberships();
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_membership.name,
  toolDefinitions.get_membership.description,
  toolDefinitions.get_membership.inputSchema.shape,
  async ({ membership_id }) => {
    const result = await client.getMembership(membership_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ACCESS (EXTENDED) ============
server.tool(
  toolDefinitions.list_access_bookmarks.name,
  toolDefinitions.list_access_bookmarks.description,
  toolDefinitions.list_access_bookmarks.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessBookmarks(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_bookmark.name,
  toolDefinitions.get_access_bookmark.description,
  toolDefinitions.get_access_bookmark.inputSchema.shape,
  async ({ account_id, bookmark_id }) => {
    const result = await client.getAccessBookmark(account_id, bookmark_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_certificates.name,
  toolDefinitions.list_access_certificates.description,
  toolDefinitions.list_access_certificates.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessCertificates(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_certificate.name,
  toolDefinitions.get_access_certificate.description,
  toolDefinitions.get_access_certificate.inputSchema.shape,
  async ({ account_id, certificate_id }) => {
    const result = await client.getAccessCertificate(account_id, certificate_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_certificate_settings.name,
  toolDefinitions.get_access_certificate_settings.description,
  toolDefinitions.get_access_certificate_settings.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getAccessCertificateSettings(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_custom_pages.name,
  toolDefinitions.list_access_custom_pages.description,
  toolDefinitions.list_access_custom_pages.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessCustomPages(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_custom_page.name,
  toolDefinitions.get_access_custom_page.description,
  toolDefinitions.get_access_custom_page.inputSchema.shape,
  async ({ account_id, custom_page_id }) => {
    const result = await client.getAccessCustomPage(account_id, custom_page_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_identity_providers.name,
  toolDefinitions.list_access_identity_providers.description,
  toolDefinitions.list_access_identity_providers.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessIdentityProviders(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_identity_provider.name,
  toolDefinitions.get_access_identity_provider.description,
  toolDefinitions.get_access_identity_provider.inputSchema.shape,
  async ({ account_id, identity_provider_id }) => {
    const result = await client.getAccessIdentityProvider(account_id, identity_provider_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_keys.name,
  toolDefinitions.get_access_keys.description,
  toolDefinitions.get_access_keys.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getAccessKeys(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_logs.name,
  toolDefinitions.list_access_logs.description,
  toolDefinitions.list_access_logs.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessLogs(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_organization.name,
  toolDefinitions.get_access_organization.description,
  toolDefinitions.get_access_organization.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getAccessOrganization(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_tags.name,
  toolDefinitions.list_access_tags.description,
  toolDefinitions.list_access_tags.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessTags(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_access_tag.name,
  toolDefinitions.get_access_tag.description,
  toolDefinitions.get_access_tag.inputSchema.shape,
  async ({ account_id, tag_name }) => {
    const result = await client.getAccessTag(account_id, tag_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_users.name,
  toolDefinitions.list_access_users.description,
  toolDefinitions.list_access_users.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccessUsers(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_user_active_sessions.name,
  toolDefinitions.list_access_user_active_sessions.description,
  toolDefinitions.list_access_user_active_sessions.inputSchema.shape,
  async ({ account_id, user_id }) => {
    const result = await client.listAccessUserActiveSessions(account_id, user_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_access_user_failed_logins.name,
  toolDefinitions.list_access_user_failed_logins.description,
  toolDefinitions.list_access_user_failed_logins.inputSchema.shape,
  async ({ account_id, user_id }) => {
    const result = await client.listAccessUserFailedLogins(account_id, user_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ AI GATEWAY (EXTENDED) ============
server.tool(
  toolDefinitions.list_ai_gateway_datasets.name,
  toolDefinitions.list_ai_gateway_datasets.description,
  toolDefinitions.list_ai_gateway_datasets.inputSchema.shape,
  async ({ account_id, gateway_id }) => {
    const result = await client.listAiGatewayDatasets(account_id, gateway_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ai_gateway_dataset.name,
  toolDefinitions.get_ai_gateway_dataset.description,
  toolDefinitions.get_ai_gateway_dataset.inputSchema.shape,
  async ({ account_id, gateway_id, dataset_id }) => {
    const result = await client.getAiGatewayDataset(account_id, gateway_id, dataset_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ai_gateway_evaluations.name,
  toolDefinitions.list_ai_gateway_evaluations.description,
  toolDefinitions.list_ai_gateway_evaluations.inputSchema.shape,
  async ({ account_id, gateway_id }) => {
    const result = await client.listAiGatewayEvaluations(account_id, gateway_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ai_gateway_evaluation.name,
  toolDefinitions.get_ai_gateway_evaluation.description,
  toolDefinitions.get_ai_gateway_evaluation.inputSchema.shape,
  async ({ account_id, gateway_id, evaluation_id }) => {
    const result = await client.getAiGatewayEvaluation(account_id, gateway_id, evaluation_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ai_gateway_routes.name,
  toolDefinitions.list_ai_gateway_routes.description,
  toolDefinitions.list_ai_gateway_routes.inputSchema.shape,
  async ({ account_id, gateway_id }) => {
    const result = await client.listAiGatewayRoutes(account_id, gateway_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ai_gateway_route.name,
  toolDefinitions.get_ai_gateway_route.description,
  toolDefinitions.get_ai_gateway_route.inputSchema.shape,
  async ({ account_id, gateway_id, route_id }) => {
    const result = await client.getAiGatewayRoute(account_id, gateway_id, route_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ IP ADDRESSING (BYOIP) ============
server.tool(
  toolDefinitions.list_address_maps.name,
  toolDefinitions.list_address_maps.description,
  toolDefinitions.list_address_maps.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAddressMaps(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_address_map.name,
  toolDefinitions.get_address_map.description,
  toolDefinitions.get_address_map.inputSchema.shape,
  async ({ account_id, address_map_id }) => {
    const result = await client.getAddressMap(account_id, address_map_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ip_prefixes.name,
  toolDefinitions.list_ip_prefixes.description,
  toolDefinitions.list_ip_prefixes.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listIpPrefixes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ip_prefix.name,
  toolDefinitions.get_ip_prefix.description,
  toolDefinitions.get_ip_prefix.inputSchema.shape,
  async ({ account_id, prefix_id }) => {
    const result = await client.getIpPrefix(account_id, prefix_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ip_prefix_bgp_status.name,
  toolDefinitions.get_ip_prefix_bgp_status.description,
  toolDefinitions.get_ip_prefix_bgp_status.inputSchema.shape,
  async ({ account_id, prefix_id }) => {
    const result = await client.getIpPrefixBgpStatus(account_id, prefix_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ip_prefix_delegations.name,
  toolDefinitions.list_ip_prefix_delegations.description,
  toolDefinitions.list_ip_prefix_delegations.inputSchema.shape,
  async ({ account_id, prefix_id }) => {
    const result = await client.listIpPrefixDelegations(account_id, prefix_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_addressing_services.name,
  toolDefinitions.list_addressing_services.description,
  toolDefinitions.list_addressing_services.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAddressingServices(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ URL SCANNER ============
server.tool(
  toolDefinitions.get_url_scan.name,
  toolDefinitions.get_url_scan.description,
  toolDefinitions.get_url_scan.inputSchema.shape,
  async ({ account_id, scan_id }) => {
    const result = await client.getUrlScan(account_id, scan_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_url_scan_har.name,
  toolDefinitions.get_url_scan_har.description,
  toolDefinitions.get_url_scan_har.inputSchema.shape,
  async ({ account_id, scan_id }) => {
    const result = await client.getUrlScanHar(account_id, scan_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ AI SEARCH ============
server.tool(
  toolDefinitions.list_ai_search_instances.name,
  toolDefinitions.list_ai_search_instances.description,
  toolDefinitions.list_ai_search_instances.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAiSearchInstances(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ai_search_instance.name,
  toolDefinitions.get_ai_search_instance.description,
  toolDefinitions.get_ai_search_instance.inputSchema.shape,
  async ({ account_id, instance_id }) => {
    const result = await client.getAiSearchInstance(account_id, instance_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ai_search_items.name,
  toolDefinitions.list_ai_search_items.description,
  toolDefinitions.list_ai_search_items.inputSchema.shape,
  async ({ account_id, instance_id }) => {
    const result = await client.listAiSearchItems(account_id, instance_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_ai_search_jobs.name,
  toolDefinitions.list_ai_search_jobs.description,
  toolDefinitions.list_ai_search_jobs.inputSchema.shape,
  async ({ account_id, instance_id }) => {
    const result = await client.listAiSearchJobs(account_id, instance_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_ai_search_job.name,
  toolDefinitions.get_ai_search_job.description,
  toolDefinitions.get_ai_search_job.inputSchema.shape,
  async ({ account_id, instance_id, job_id }) => {
    const result = await client.getAiSearchJob(account_id, instance_id, job_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ WORKERS BUILDS ============
server.tool(
  toolDefinitions.list_worker_builds.name,
  toolDefinitions.list_worker_builds.description,
  toolDefinitions.list_worker_builds.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listWorkerBuilds(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_worker_build.name,
  toolDefinitions.get_worker_build.description,
  toolDefinitions.get_worker_build.inputSchema.shape,
  async ({ account_id, build_id }) => {
    const result = await client.getWorkerBuild(account_id, build_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ WORKERS WORKFLOWS ============
server.tool(
  toolDefinitions.list_workflows.name,
  toolDefinitions.list_workflows.description,
  toolDefinitions.list_workflows.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listWorkflows(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_workflow.name,
  toolDefinitions.get_workflow.description,
  toolDefinitions.get_workflow.inputSchema.shape,
  async ({ account_id, workflow_name }) => {
    const result = await client.getWorkflow(account_id, workflow_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_workflow_instances.name,
  toolDefinitions.list_workflow_instances.description,
  toolDefinitions.list_workflow_instances.inputSchema.shape,
  async ({ account_id, workflow_name }) => {
    const result = await client.listWorkflowInstances(account_id, workflow_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_workflow_instance.name,
  toolDefinitions.get_workflow_instance.description,
  toolDefinitions.get_workflow_instance.inputSchema.shape,
  async ({ account_id, workflow_name, instance_id }) => {
    const result = await client.getWorkflowInstance(account_id, workflow_name, instance_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ CNI (INTERCONNECT) ============
server.tool(
  toolDefinitions.list_cni_interconnects.name,
  toolDefinitions.list_cni_interconnects.description,
  toolDefinitions.list_cni_interconnects.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCniInterconnects(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cni_interconnect.name,
  toolDefinitions.get_cni_interconnect.description,
  toolDefinitions.get_cni_interconnect.inputSchema.shape,
  async ({ account_id, interconnect_id }) => {
    const result = await client.getCniInterconnect(account_id, interconnect_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cni_slots.name,
  toolDefinitions.list_cni_slots.description,
  toolDefinitions.list_cni_slots.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCniSlots(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cni_settings.name,
  toolDefinitions.get_cni_settings.description,
  toolDefinitions.get_cni_settings.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getCniSettings(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ R2 PIPELINES ============
server.tool(
  toolDefinitions.list_r2_pipelines.name,
  toolDefinitions.list_r2_pipelines.description,
  toolDefinitions.list_r2_pipelines.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listR2Pipelines(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_r2_pipeline.name,
  toolDefinitions.get_r2_pipeline.description,
  toolDefinitions.get_r2_pipeline.inputSchema.shape,
  async ({ account_id, pipeline_name }) => {
    const result = await client.getR2Pipeline(account_id, pipeline_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ IAM/PERMISSIONS ============
server.tool(
  toolDefinitions.list_permission_groups.name,
  toolDefinitions.list_permission_groups.description,
  toolDefinitions.list_permission_groups.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listPermissionGroups(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_permission_group.name,
  toolDefinitions.get_permission_group.description,
  toolDefinitions.get_permission_group.inputSchema.shape,
  async ({ account_id, group_id }) => {
    const result = await client.getPermissionGroup(account_id, group_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_resource_groups.name,
  toolDefinitions.list_resource_groups.description,
  toolDefinitions.list_resource_groups.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listResourceGroups(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_resource_group.name,
  toolDefinitions.get_resource_group.description,
  toolDefinitions.get_resource_group.inputSchema.shape,
  async ({ account_id, group_id }) => {
    const result = await client.getResourceGroup(account_id, group_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZERO TRUST RISK SCORING ============
server.tool(
  toolDefinitions.list_risk_scoring_behaviors.name,
  toolDefinitions.list_risk_scoring_behaviors.description,
  toolDefinitions.list_risk_scoring_behaviors.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listRiskScoringBehaviors(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_risk_scoring_integrations.name,
  toolDefinitions.list_risk_scoring_integrations.description,
  toolDefinitions.list_risk_scoring_integrations.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listRiskScoringIntegrations(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_risk_scoring_integration.name,
  toolDefinitions.get_risk_scoring_integration.description,
  toolDefinitions.get_risk_scoring_integration.inputSchema.shape,
  async ({ account_id, integration_id }) => {
    const result = await client.getRiskScoringIntegration(account_id, integration_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ R2 CATALOG ============
server.tool(
  toolDefinitions.list_r2_catalogs.name,
  toolDefinitions.list_r2_catalogs.description,
  toolDefinitions.list_r2_catalogs.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listR2Catalogs(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_r2_catalog.name,
  toolDefinitions.get_r2_catalog.description,
  toolDefinitions.get_r2_catalog.inputSchema.shape,
  async ({ account_id, catalog_name }) => {
    const result = await client.getR2Catalog(account_id, catalog_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ TEAM NETWORK ROUTES ============
server.tool(
  toolDefinitions.list_teamnet_routes.name,
  toolDefinitions.list_teamnet_routes.description,
  toolDefinitions.list_teamnet_routes.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listTeamnetRoutes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_teamnet_virtual_networks.name,
  toolDefinitions.list_teamnet_virtual_networks.description,
  toolDefinitions.list_teamnet_virtual_networks.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listTeamnetVirtualNetworks(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_teamnet_virtual_network.name,
  toolDefinitions.get_teamnet_virtual_network.description,
  toolDefinitions.get_teamnet_virtual_network.inputSchema.shape,
  async ({ account_id, vnet_id }) => {
    const result = await client.getTeamnetVirtualNetwork(account_id, vnet_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ SECRETS STORE ============
server.tool(
  toolDefinitions.list_secrets_stores.name,
  toolDefinitions.list_secrets_stores.description,
  toolDefinitions.list_secrets_stores.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listSecretsStores(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_secrets_store.name,
  toolDefinitions.get_secrets_store.description,
  toolDefinitions.get_secrets_store.inputSchema.shape,
  async ({ account_id, store_id }) => {
    const result = await client.getSecretsStore(account_id, store_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_secrets_store_secrets.name,
  toolDefinitions.list_secrets_store_secrets.description,
  toolDefinitions.list_secrets_store_secrets.inputSchema.shape,
  async ({ account_id, store_id }) => {
    const result = await client.listSecretsStoreSecrets(account_id, store_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ PACKET CAPTURES ============
server.tool(
  toolDefinitions.list_pcaps.name,
  toolDefinitions.list_pcaps.description,
  toolDefinitions.list_pcaps.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listPcaps(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_pcap.name,
  toolDefinitions.get_pcap.description,
  toolDefinitions.get_pcap.inputSchema.shape,
  async ({ account_id, pcap_id }) => {
    const result = await client.getPcap(account_id, pcap_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_pcap_ownership.name,
  toolDefinitions.get_pcap_ownership.description,
  toolDefinitions.get_pcap_ownership.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getPcapOwnership(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ MAGIC NETWORK MONITORING ============
server.tool(
  toolDefinitions.get_mnm_config.name,
  toolDefinitions.get_mnm_config.description,
  toolDefinitions.get_mnm_config.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getMnmConfig(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_mnm_rules.name,
  toolDefinitions.list_mnm_rules.description,
  toolDefinitions.list_mnm_rules.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listMnmRules(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_mnm_rule.name,
  toolDefinitions.get_mnm_rule.description,
  toolDefinitions.get_mnm_rule.inputSchema.shape,
  async ({ account_id, rule_id }) => {
    const result = await client.getMnmRule(account_id, rule_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ WARP CONNECTOR ============
server.tool(
  toolDefinitions.list_warp_connectors.name,
  toolDefinitions.list_warp_connectors.description,
  toolDefinitions.list_warp_connectors.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listWarpConnectors(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_warp_connector.name,
  toolDefinitions.get_warp_connector.description,
  toolDefinitions.get_warp_connector.inputSchema.shape,
  async ({ account_id, connector_id }) => {
    const result = await client.getWarpConnector(account_id, connector_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ MTLS CERTIFICATES (ACCOUNT) ============
server.tool(
  toolDefinitions.list_account_mtls_certificates.name,
  toolDefinitions.list_account_mtls_certificates.description,
  toolDefinitions.list_account_mtls_certificates.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccountMtlsCertificates(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_account_mtls_certificate.name,
  toolDefinitions.get_account_mtls_certificate.description,
  toolDefinitions.get_account_mtls_certificate.inputSchema.shape,
  async ({ account_id, certificate_id }) => {
    const result = await client.getAccountMtlsCertificate(account_id, certificate_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ACCOUNT DNS SETTINGS ============
server.tool(
  toolDefinitions.get_account_dns_settings.name,
  toolDefinitions.get_account_dns_settings.description,
  toolDefinitions.get_account_dns_settings.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getAccountDnsSettings(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dns_views.name,
  toolDefinitions.list_dns_views.description,
  toolDefinitions.list_dns_views.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDnsViews(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dns_view.name,
  toolDefinitions.get_dns_view.description,
  toolDefinitions.get_dns_view.inputSchema.shape,
  async ({ account_id, view_id }) => {
    const result = await client.getDnsView(account_id, view_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: API SCHEMA VALIDATION ============
server.tool(
  toolDefinitions.get_schema_validation_settings.name,
  toolDefinitions.get_schema_validation_settings.description,
  toolDefinitions.get_schema_validation_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSchemaValidationSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_api_schemas.name,
  toolDefinitions.list_api_schemas.description,
  toolDefinitions.list_api_schemas.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listApiSchemas(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: TOKEN VALIDATION ============
server.tool(
  toolDefinitions.get_token_validation_settings.name,
  toolDefinitions.get_token_validation_settings.description,
  toolDefinitions.get_token_validation_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getTokenValidationSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: SMART SHIELD ============
server.tool(
  toolDefinitions.get_smart_shield_settings.name,
  toolDefinitions.get_smart_shield_settings.description,
  toolDefinitions.get_smart_shield_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSmartShieldSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: LOGS ============
server.tool(
  toolDefinitions.get_zone_logs_retention.name,
  toolDefinitions.get_zone_logs_retention.description,
  toolDefinitions.get_zone_logs_retention.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getZoneLogsRetention(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: LEAKED CREDENTIAL CHECKS ============
server.tool(
  toolDefinitions.get_leaked_credential_check_settings.name,
  toolDefinitions.get_leaked_credential_check_settings.description,
  toolDefinitions.get_leaked_credential_check_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getLeakedCredentialCheckSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_leaked_credential_detections.name,
  toolDefinitions.list_leaked_credential_detections.description,
  toolDefinitions.list_leaked_credential_detections.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listLeakedCredentialDetections(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: ADVANCED CERTIFICATE MANAGER ============
server.tool(
  toolDefinitions.get_total_tls_settings.name,
  toolDefinitions.get_total_tls_settings.description,
  toolDefinitions.get_total_tls_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getTotalTlsSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: DNS ANALYTICS ============
server.tool(
  toolDefinitions.get_dns_analytics_report.name,
  toolDefinitions.get_dns_analytics_report.description,
  toolDefinitions.get_dns_analytics_report.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getDnsAnalyticsReport(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: FRAUD DETECTION ============
server.tool(
  toolDefinitions.get_fraud_detection_settings.name,
  toolDefinitions.get_fraud_detection_settings.description,
  toolDefinitions.get_fraud_detection_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getFraudDetectionSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: CLOUD CONNECTOR ============
server.tool(
  toolDefinitions.list_cloud_connector_rules.name,
  toolDefinitions.list_cloud_connector_rules.description,
  toolDefinitions.list_cloud_connector_rules.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listCloudConnectorRules(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: DCV DELEGATION ============
server.tool(
  toolDefinitions.get_dcv_delegation.name,
  toolDefinitions.get_dcv_delegation.description,
  toolDefinitions.get_dcv_delegation.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getDcvDelegation(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ INTEL ============
server.tool(
  toolDefinitions.get_intel_asn.name,
  toolDefinitions.get_intel_asn.description,
  toolDefinitions.get_intel_asn.inputSchema.shape,
  async ({ account_id, asn }) => {
    const result = await client.getIntelAsn(account_id, asn);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_intel_domain.name,
  toolDefinitions.get_intel_domain.description,
  toolDefinitions.get_intel_domain.inputSchema.shape,
  async ({ account_id, domain }) => {
    const result = await client.getIntelDomain(account_id, domain);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_intel_domain_history.name,
  toolDefinitions.get_intel_domain_history.description,
  toolDefinitions.get_intel_domain_history.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getIntelDomainHistory(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_intel_ip.name,
  toolDefinitions.get_intel_ip.description,
  toolDefinitions.get_intel_ip.inputSchema.shape,
  async ({ account_id, ipv4, ipv6 }) => {
    const result = await client.getIntelIp(account_id, ipv4, ipv6);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_intel_whois.name,
  toolDefinitions.get_intel_whois.description,
  toolDefinitions.get_intel_whois.inputSchema.shape,
  async ({ account_id, domain }) => {
    const result = await client.getIntelWhois(account_id, domain);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_intel_indicator_feeds.name,
  toolDefinitions.list_intel_indicator_feeds.description,
  toolDefinitions.list_intel_indicator_feeds.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listIntelIndicatorFeeds(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_intel_indicator_feed.name,
  toolDefinitions.get_intel_indicator_feed.description,
  toolDefinitions.get_intel_indicator_feed.inputSchema.shape,
  async ({ account_id, feed_id }) => {
    const result = await client.getIntelIndicatorFeed(account_id, feed_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_intel_sinkholes.name,
  toolDefinitions.list_intel_sinkholes.description,
  toolDefinitions.list_intel_sinkholes.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listIntelSinkholes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_intel_ip_lists.name,
  toolDefinitions.list_intel_ip_lists.description,
  toolDefinitions.list_intel_ip_lists.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listIntelIpLists(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ RULES/LISTS ============
server.tool(
  toolDefinitions.list_account_rules_lists.name,
  toolDefinitions.list_account_rules_lists.description,
  toolDefinitions.list_account_rules_lists.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccountRulesLists(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_account_rules_list.name,
  toolDefinitions.get_account_rules_list.description,
  toolDefinitions.get_account_rules_list.inputSchema.shape,
  async ({ account_id, list_id }) => {
    const result = await client.getAccountRulesList(account_id, list_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_account_rules_list_items.name,
  toolDefinitions.list_account_rules_list_items.description,
  toolDefinitions.list_account_rules_list_items.inputSchema.shape,
  async ({ account_id, list_id }) => {
    const result = await client.listAccountRulesListItems(account_id, list_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ API TOKENS ============
server.tool(
  toolDefinitions.list_account_tokens.name,
  toolDefinitions.list_account_tokens.description,
  toolDefinitions.list_account_tokens.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAccountTokens(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_account_token.name,
  toolDefinitions.get_account_token.description,
  toolDefinitions.get_account_token.inputSchema.shape,
  async ({ account_id, token_id }) => {
    const result = await client.getAccountToken(account_id, token_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.verify_account_token.name,
  toolDefinitions.verify_account_token.description,
  toolDefinitions.verify_account_token.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.verifyAccountToken(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_token_permission_groups.name,
  toolDefinitions.list_token_permission_groups.description,
  toolDefinitions.list_token_permission_groups.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listTokenPermissionGroups(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ RUM ============
server.tool(
  toolDefinitions.list_rum_sites.name,
  toolDefinitions.list_rum_sites.description,
  toolDefinitions.list_rum_sites.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listRumSites(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_rum_site.name,
  toolDefinitions.get_rum_site.description,
  toolDefinitions.get_rum_site.inputSchema.shape,
  async ({ account_id, site_id }) => {
    const result = await client.getRumSite(account_id, site_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ABUSE REPORTS ============
server.tool(
  toolDefinitions.list_abuse_reports.name,
  toolDefinitions.list_abuse_reports.description,
  toolDefinitions.list_abuse_reports.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listAbuseReports(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_abuse_report.name,
  toolDefinitions.get_abuse_report.description,
  toolDefinitions.get_abuse_report.inputSchema.shape,
  async ({ account_id, report_id }) => {
    const result = await client.getAbuseReport(account_id, report_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ INFRASTRUCTURE TARGETS ============
server.tool(
  toolDefinitions.list_infrastructure_targets.name,
  toolDefinitions.list_infrastructure_targets.description,
  toolDefinitions.list_infrastructure_targets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listInfrastructureTargets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_infrastructure_target.name,
  toolDefinitions.get_infrastructure_target.description,
  toolDefinitions.get_infrastructure_target.inputSchema.shape,
  async ({ account_id, target_id }) => {
    const result = await client.getInfrastructureTarget(account_id, target_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ CONNECTIVITY SERVICES ============
server.tool(
  toolDefinitions.list_connectivity_services.name,
  toolDefinitions.list_connectivity_services.description,
  toolDefinitions.list_connectivity_services.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listConnectivityServices(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_connectivity_service.name,
  toolDefinitions.get_connectivity_service.description,
  toolDefinitions.get_connectivity_service.inputSchema.shape,
  async ({ account_id, service_id }) => {
    const result = await client.getConnectivityService(account_id, service_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ DIAGNOSTICS ============
server.tool(
  toolDefinitions.list_endpoint_healthchecks.name,
  toolDefinitions.list_endpoint_healthchecks.description,
  toolDefinitions.list_endpoint_healthchecks.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEndpointHealthchecks(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_endpoint_healthcheck.name,
  toolDefinitions.get_endpoint_healthcheck.description,
  toolDefinitions.get_endpoint_healthcheck.inputSchema.shape,
  async ({ account_id, healthcheck_id }) => {
    const result = await client.getEndpointHealthcheck(account_id, healthcheck_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ CONTAINERS ============
server.tool(
  toolDefinitions.list_containers.name,
  toolDefinitions.list_containers.description,
  toolDefinitions.list_containers.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listContainers(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ EVENT NOTIFICATIONS ============
server.tool(
  toolDefinitions.get_r2_event_notification_config.name,
  toolDefinitions.get_r2_event_notification_config.description,
  toolDefinitions.get_r2_event_notification_config.inputSchema.shape,
  async ({ account_id, bucket_name }) => {
    const result = await client.getR2EventNotificationConfig(account_id, bucket_name);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: API GATEWAY ============
server.tool(
  toolDefinitions.get_api_gateway_config.name,
  toolDefinitions.get_api_gateway_config.description,
  toolDefinitions.get_api_gateway_config.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getApiGatewayConfig(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_api_gateway_discovery.name,
  toolDefinitions.get_api_gateway_discovery.description,
  toolDefinitions.get_api_gateway_discovery.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getApiGatewayDiscovery(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_api_gateway_operations.name,
  toolDefinitions.list_api_gateway_operations.description,
  toolDefinitions.list_api_gateway_operations.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listApiGatewayOperations(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_api_gateway_operation.name,
  toolDefinitions.get_api_gateway_operation.description,
  toolDefinitions.get_api_gateway_operation.inputSchema.shape,
  async ({ zone_id, operation_id }) => {
    const result = await client.getApiGatewayOperation(zone_id, operation_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_api_gateway_schemas.name,
  toolDefinitions.list_api_gateway_schemas.description,
  toolDefinitions.list_api_gateway_schemas.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listApiGatewaySchemas(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_api_gateway_user_schemas.name,
  toolDefinitions.list_api_gateway_user_schemas.description,
  toolDefinitions.list_api_gateway_user_schemas.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.listApiGatewayUserSchemas(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_api_gateway_user_schema.name,
  toolDefinitions.get_api_gateway_user_schema.description,
  toolDefinitions.get_api_gateway_user_schema.inputSchema.shape,
  async ({ zone_id, schema_id }) => {
    const result = await client.getApiGatewayUserSchema(zone_id, schema_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_api_gateway_settings.name,
  toolDefinitions.get_api_gateway_settings.description,
  toolDefinitions.get_api_gateway_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getApiGatewaySettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: SPECTRUM (Analytics) ============
server.tool(
  toolDefinitions.get_spectrum_analytics_summary.name,
  toolDefinitions.get_spectrum_analytics_summary.description,
  toolDefinitions.get_spectrum_analytics_summary.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getSpectrumAnalyticsSummary(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: CONTENT UPLOAD SCAN ============
server.tool(
  toolDefinitions.get_content_upload_scan_settings.name,
  toolDefinitions.get_content_upload_scan_settings.description,
  toolDefinitions.get_content_upload_scan_settings.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getContentUploadScanSettings(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZONE: HOLD ============
server.tool(
  toolDefinitions.get_zone_hold.name,
  toolDefinitions.get_zone_hold.description,
  toolDefinitions.get_zone_hold.inputSchema.shape,
  async ({ zone_id }) => {
    const result = await client.getZoneHold(zone_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ SHARES (R2) ============
server.tool(
  toolDefinitions.get_r2_share.name,
  toolDefinitions.get_r2_share.description,
  toolDefinitions.get_r2_share.inputSchema.shape,
  async ({ account_id, share_id }) => {
    const result = await client.getR2Share(account_id, share_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_r2_share_recipients.name,
  toolDefinitions.list_r2_share_recipients.description,
  toolDefinitions.list_r2_share_recipients.inputSchema.shape,
  async ({ account_id, share_id }) => {
    const result = await client.listR2ShareRecipients(account_id, share_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_r2_share_resources.name,
  toolDefinitions.list_r2_share_resources.description,
  toolDefinitions.list_r2_share_resources.inputSchema.shape,
  async ({ account_id, share_id }) => {
    const result = await client.listR2ShareResources(account_id, share_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ SLURPER (MIGRATION) ============
server.tool(
  toolDefinitions.list_slurper_jobs.name,
  toolDefinitions.list_slurper_jobs.description,
  toolDefinitions.list_slurper_jobs.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listSlurperJobs(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_slurper_job.name,
  toolDefinitions.get_slurper_job.description,
  toolDefinitions.get_slurper_job.inputSchema.shape,
  async ({ account_id, job_id }) => {
    const result = await client.getSlurperJob(account_id, job_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_slurper_job_progress.name,
  toolDefinitions.get_slurper_job_progress.description,
  toolDefinitions.get_slurper_job_progress.inputSchema.shape,
  async ({ account_id, job_id }) => {
    const result = await client.getSlurperJobProgress(account_id, job_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ BOTNET FEED ============
server.tool(
  toolDefinitions.get_botnet_feed_asn_config.name,
  toolDefinitions.get_botnet_feed_asn_config.description,
  toolDefinitions.get_botnet_feed_asn_config.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getBotnetFeedAsnConfig(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_botnet_feed_asn_report.name,
  toolDefinitions.get_botnet_feed_asn_report.description,
  toolDefinitions.get_botnet_feed_asn_report.inputSchema.shape,
  async ({ account_id, asn_id }) => {
    const result = await client.getBotnetFeedAsnReport(account_id, asn_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ AUTORAG ============
server.tool(
  toolDefinitions.list_autorag_files.name,
  toolDefinitions.list_autorag_files.description,
  toolDefinitions.list_autorag_files.inputSchema.shape,
  async ({ account_id, rag_id }) => {
    const result = await client.listAutoragFiles(account_id, rag_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_autorag_jobs.name,
  toolDefinitions.list_autorag_jobs.description,
  toolDefinitions.list_autorag_jobs.inputSchema.shape,
  async ({ account_id, rag_id }) => {
    const result = await client.listAutoragJobs(account_id, rag_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_autorag_job.name,
  toolDefinitions.get_autorag_job.description,
  toolDefinitions.get_autorag_job.inputSchema.shape,
  async ({ account_id, rag_id, job_id }) => {
    const result = await client.getAutoragJob(account_id, rag_id, job_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ DEX (Digital Experience) ============
server.tool(
  toolDefinitions.list_dex_colos.name,
  toolDefinitions.list_dex_colos.description,
  toolDefinitions.list_dex_colos.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDexColos(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dex_fleet_status_devices.name,
  toolDefinitions.list_dex_fleet_status_devices.description,
  toolDefinitions.list_dex_fleet_status_devices.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDexFleetStatusDevices(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_fleet_status_live.name,
  toolDefinitions.get_dex_fleet_status_live.description,
  toolDefinitions.get_dex_fleet_status_live.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getDexFleetStatusLive(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_fleet_status_over_time.name,
  toolDefinitions.get_dex_fleet_status_over_time.description,
  toolDefinitions.get_dex_fleet_status_over_time.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getDexFleetStatusOverTime(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dex_tests_overview.name,
  toolDefinitions.list_dex_tests_overview.description,
  toolDefinitions.list_dex_tests_overview.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDexTestsOverview(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_tests_unique_devices.name,
  toolDefinitions.get_dex_tests_unique_devices.description,
  toolDefinitions.get_dex_tests_unique_devices.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getDexTestsUniqueDevices(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_http_test.name,
  toolDefinitions.get_dex_http_test.description,
  toolDefinitions.get_dex_http_test.inputSchema.shape,
  async ({ account_id, test_id }) => {
    const result = await client.getDexHttpTest(account_id, test_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_traceroute_test.name,
  toolDefinitions.get_dex_traceroute_test.description,
  toolDefinitions.get_dex_traceroute_test.inputSchema.shape,
  async ({ account_id, test_id }) => {
    const result = await client.getDexTracerouteTest(account_id, test_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dex_rules.name,
  toolDefinitions.list_dex_rules.description,
  toolDefinitions.list_dex_rules.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDexRules(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_rule.name,
  toolDefinitions.get_dex_rule.description,
  toolDefinitions.get_dex_rule.inputSchema.shape,
  async ({ account_id, rule_id }) => {
    const result = await client.getDexRule(account_id, rule_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_dex_commands.name,
  toolDefinitions.list_dex_commands.description,
  toolDefinitions.list_dex_commands.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listDexCommands(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_dex_commands_quota.name,
  toolDefinitions.get_dex_commands_quota.description,
  toolDefinitions.get_dex_commands_quota.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getDexCommandsQuota(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ BRAND PROTECTION ============
server.tool(
  toolDefinitions.list_brand_protection_alerts.name,
  toolDefinitions.list_brand_protection_alerts.description,
  toolDefinitions.list_brand_protection_alerts.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionAlerts(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_brands.name,
  toolDefinitions.list_brand_protection_brands.description,
  toolDefinitions.list_brand_protection_brands.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionBrands(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_logos.name,
  toolDefinitions.list_brand_protection_logos.description,
  toolDefinitions.list_brand_protection_logos.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionLogos(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_brand_protection_logo.name,
  toolDefinitions.get_brand_protection_logo.description,
  toolDefinitions.get_brand_protection_logo.inputSchema.shape,
  async ({ account_id, logo_id }) => {
    const result = await client.getBrandProtectionLogo(account_id, logo_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_matches.name,
  toolDefinitions.list_brand_protection_matches.description,
  toolDefinitions.list_brand_protection_matches.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionMatches(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_logo_matches.name,
  toolDefinitions.list_brand_protection_logo_matches.description,
  toolDefinitions.list_brand_protection_logo_matches.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionLogoMatches(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_queries.name,
  toolDefinitions.list_brand_protection_queries.description,
  toolDefinitions.list_brand_protection_queries.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionQueries(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_brand_protection_url_info.name,
  toolDefinitions.get_brand_protection_url_info.description,
  toolDefinitions.get_brand_protection_url_info.inputSchema.shape,
  async ({ account_id, url }) => {
    const result = await client.getBrandProtectionUrlInfo(account_id, url);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_brand_protection_domain_info.name,
  toolDefinitions.get_brand_protection_domain_info.description,
  toolDefinitions.get_brand_protection_domain_info.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getBrandProtectionDomainInfo(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_tracked_domains.name,
  toolDefinitions.list_brand_protection_tracked_domains.description,
  toolDefinitions.list_brand_protection_tracked_domains.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionTrackedDomains(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_brand_protection_recent_submissions.name,
  toolDefinitions.list_brand_protection_recent_submissions.description,
  toolDefinitions.list_brand_protection_recent_submissions.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listBrandProtectionRecentSubmissions(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ EMAIL SECURITY ============
server.tool(
  toolDefinitions.list_email_security_investigate.name,
  toolDefinitions.list_email_security_investigate.description,
  toolDefinitions.list_email_security_investigate.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecurityInvestigate(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_security_message.name,
  toolDefinitions.get_email_security_message.description,
  toolDefinitions.get_email_security_message.inputSchema.shape,
  async ({ account_id, postfix_id }) => {
    const result = await client.getEmailSecurityMessage(account_id, postfix_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_security_message_detections.name,
  toolDefinitions.get_email_security_message_detections.description,
  toolDefinitions.get_email_security_message_detections.inputSchema.shape,
  async ({ account_id, postfix_id }) => {
    const result = await client.getEmailSecurityMessageDetections(account_id, postfix_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_security_submissions.name,
  toolDefinitions.list_email_security_submissions.description,
  toolDefinitions.list_email_security_submissions.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecuritySubmissions(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_security_allow_policies.name,
  toolDefinitions.list_email_security_allow_policies.description,
  toolDefinitions.list_email_security_allow_policies.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecurityAllowPolicies(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_security_allow_policy.name,
  toolDefinitions.get_email_security_allow_policy.description,
  toolDefinitions.get_email_security_allow_policy.inputSchema.shape,
  async ({ account_id, policy_id }) => {
    const result = await client.getEmailSecurityAllowPolicy(account_id, policy_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_security_block_senders.name,
  toolDefinitions.list_email_security_block_senders.description,
  toolDefinitions.list_email_security_block_senders.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecurityBlockSenders(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_security_block_sender.name,
  toolDefinitions.get_email_security_block_sender.description,
  toolDefinitions.get_email_security_block_sender.inputSchema.shape,
  async ({ account_id, pattern_id }) => {
    const result = await client.getEmailSecurityBlockSender(account_id, pattern_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_security_domains.name,
  toolDefinitions.list_email_security_domains.description,
  toolDefinitions.list_email_security_domains.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecurityDomains(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_security_domain.name,
  toolDefinitions.get_email_security_domain.description,
  toolDefinitions.get_email_security_domain.inputSchema.shape,
  async ({ account_id, domain_id }) => {
    const result = await client.getEmailSecurityDomain(account_id, domain_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_security_impersonation_registry.name,
  toolDefinitions.list_email_security_impersonation_registry.description,
  toolDefinitions.list_email_security_impersonation_registry.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecurityImpersonationRegistry(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_email_security_trusted_domains.name,
  toolDefinitions.list_email_security_trusted_domains.description,
  toolDefinitions.list_email_security_trusted_domains.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listEmailSecurityTrustedDomains(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_email_security_phishguard_reports.name,
  toolDefinitions.get_email_security_phishguard_reports.description,
  toolDefinitions.get_email_security_phishguard_reports.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getEmailSecurityPhishguardReports(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ REALTIME KIT ============
server.tool(
  toolDefinitions.list_realtime_apps.name,
  toolDefinitions.list_realtime_apps.description,
  toolDefinitions.list_realtime_apps.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listRealtimeApps(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_analytics_daywise.name,
  toolDefinitions.get_realtime_analytics_daywise.description,
  toolDefinitions.get_realtime_analytics_daywise.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.getRealtimeAnalyticsDaywise(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_livestreams.name,
  toolDefinitions.list_realtime_livestreams.description,
  toolDefinitions.list_realtime_livestreams.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.listRealtimeLivestreams(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_livestream.name,
  toolDefinitions.get_realtime_livestream.description,
  toolDefinitions.get_realtime_livestream.inputSchema.shape,
  async ({ account_id, app_id, livestream_id }) => {
    const result = await client.getRealtimeLivestream(account_id, app_id, livestream_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_meetings.name,
  toolDefinitions.list_realtime_meetings.description,
  toolDefinitions.list_realtime_meetings.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.listRealtimeMeetings(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_meeting.name,
  toolDefinitions.get_realtime_meeting.description,
  toolDefinitions.get_realtime_meeting.inputSchema.shape,
  async ({ account_id, app_id, meeting_id }) => {
    const result = await client.getRealtimeMeeting(account_id, app_id, meeting_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_meeting_participants.name,
  toolDefinitions.list_realtime_meeting_participants.description,
  toolDefinitions.list_realtime_meeting_participants.inputSchema.shape,
  async ({ account_id, app_id, meeting_id }) => {
    const result = await client.listRealtimeMeetingParticipants(account_id, app_id, meeting_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_presets.name,
  toolDefinitions.list_realtime_presets.description,
  toolDefinitions.list_realtime_presets.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.listRealtimePresets(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_preset.name,
  toolDefinitions.get_realtime_preset.description,
  toolDefinitions.get_realtime_preset.inputSchema.shape,
  async ({ account_id, app_id, preset_id }) => {
    const result = await client.getRealtimePreset(account_id, app_id, preset_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_recordings.name,
  toolDefinitions.list_realtime_recordings.description,
  toolDefinitions.list_realtime_recordings.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.listRealtimeRecordings(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_recording.name,
  toolDefinitions.get_realtime_recording.description,
  toolDefinitions.get_realtime_recording.inputSchema.shape,
  async ({ account_id, app_id, recording_id }) => {
    const result = await client.getRealtimeRecording(account_id, app_id, recording_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_sessions.name,
  toolDefinitions.list_realtime_sessions.description,
  toolDefinitions.list_realtime_sessions.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.listRealtimeSessions(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_session.name,
  toolDefinitions.get_realtime_session.description,
  toolDefinitions.get_realtime_session.inputSchema.shape,
  async ({ account_id, app_id, session_id }) => {
    const result = await client.getRealtimeSession(account_id, app_id, session_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_session_summary.name,
  toolDefinitions.get_realtime_session_summary.description,
  toolDefinitions.get_realtime_session_summary.inputSchema.shape,
  async ({ account_id, app_id, session_id }) => {
    const result = await client.getRealtimeSessionSummary(account_id, app_id, session_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_session_transcript.name,
  toolDefinitions.get_realtime_session_transcript.description,
  toolDefinitions.get_realtime_session_transcript.inputSchema.shape,
  async ({ account_id, app_id, session_id }) => {
    const result = await client.getRealtimeSessionTranscript(account_id, app_id, session_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_realtime_webhooks.name,
  toolDefinitions.list_realtime_webhooks.description,
  toolDefinitions.list_realtime_webhooks.inputSchema.shape,
  async ({ account_id, app_id }) => {
    const result = await client.listRealtimeWebhooks(account_id, app_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_realtime_webhook.name,
  toolDefinitions.get_realtime_webhook.description,
  toolDefinitions.get_realtime_webhook.inputSchema.shape,
  async ({ account_id, app_id, webhook_id }) => {
    const result = await client.getRealtimeWebhook(account_id, app_id, webhook_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ ZERO TRUST SETTINGS ============
server.tool(
  toolDefinitions.get_zerotrust_connectivity_settings.name,
  toolDefinitions.get_zerotrust_connectivity_settings.description,
  toolDefinitions.get_zerotrust_connectivity_settings.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getZerotrustConnectivitySettings(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_zerotrust_hostname_routes.name,
  toolDefinitions.list_zerotrust_hostname_routes.description,
  toolDefinitions.list_zerotrust_hostname_routes.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listZerotrustHostnameRoutes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_zerotrust_hostname_route.name,
  toolDefinitions.get_zerotrust_hostname_route.description,
  toolDefinitions.get_zerotrust_hostname_route.inputSchema.shape,
  async ({ account_id, hostname_route_id }) => {
    const result = await client.getZerotrustHostnameRoute(account_id, hostname_route_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_zerotrust_subnets.name,
  toolDefinitions.list_zerotrust_subnets.description,
  toolDefinitions.list_zerotrust_subnets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listZerotrustSubnets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ============ CLOUDFORCE ONE ============
server.tool(
  toolDefinitions.list_cloudforce_one_events.name,
  toolDefinitions.list_cloudforce_one_events.description,
  toolDefinitions.list_cloudforce_one_events.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneEvents(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_event.name,
  toolDefinitions.get_cloudforce_one_event.description,
  toolDefinitions.get_cloudforce_one_event.inputSchema.shape,
  async ({ account_id, event_id }) => {
    const result = await client.getCloudforceOneEvent(account_id, event_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_events_aggregate.name,
  toolDefinitions.get_cloudforce_one_events_aggregate.description,
  toolDefinitions.get_cloudforce_one_events_aggregate.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getCloudforceOneEventsAggregate(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_categories.name,
  toolDefinitions.list_cloudforce_one_categories.description,
  toolDefinitions.list_cloudforce_one_categories.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneCategories(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_countries.name,
  toolDefinitions.list_cloudforce_one_countries.description,
  toolDefinitions.list_cloudforce_one_countries.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneCountries(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_datasets.name,
  toolDefinitions.list_cloudforce_one_datasets.description,
  toolDefinitions.list_cloudforce_one_datasets.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneDatasets(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_dataset.name,
  toolDefinitions.get_cloudforce_one_dataset.description,
  toolDefinitions.get_cloudforce_one_dataset.inputSchema.shape,
  async ({ account_id, dataset_id }) => {
    const result = await client.getCloudforceOneDataset(account_id, dataset_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_indicators.name,
  toolDefinitions.list_cloudforce_one_indicators.description,
  toolDefinitions.list_cloudforce_one_indicators.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneIndicators(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_indicator_types.name,
  toolDefinitions.list_cloudforce_one_indicator_types.description,
  toolDefinitions.list_cloudforce_one_indicator_types.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneIndicatorTypes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_tags.name,
  toolDefinitions.list_cloudforce_one_tags.description,
  toolDefinitions.list_cloudforce_one_tags.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneTags(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_target_industries.name,
  toolDefinitions.list_cloudforce_one_target_industries.description,
  toolDefinitions.list_cloudforce_one_target_industries.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneTargetIndustries(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_queries.name,
  toolDefinitions.list_cloudforce_one_queries.description,
  toolDefinitions.list_cloudforce_one_queries.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneQueries(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_query.name,
  toolDefinitions.get_cloudforce_one_query.description,
  toolDefinitions.get_cloudforce_one_query.inputSchema.shape,
  async ({ account_id, query_id }) => {
    const result = await client.getCloudforceOneQuery(account_id, query_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_request.name,
  toolDefinitions.get_cloudforce_one_request.description,
  toolDefinitions.get_cloudforce_one_request.inputSchema.shape,
  async ({ account_id, request_id }) => {
    const result = await client.getCloudforceOneRequest(account_id, request_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_requests_quota.name,
  toolDefinitions.get_cloudforce_one_requests_quota.description,
  toolDefinitions.get_cloudforce_one_requests_quota.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getCloudforceOneRequestsQuota(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.list_cloudforce_one_request_types.name,
  toolDefinitions.list_cloudforce_one_request_types.description,
  toolDefinitions.list_cloudforce_one_request_types.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.listCloudforceOneRequestTypes(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  toolDefinitions.get_cloudforce_one_scans_config.name,
  toolDefinitions.get_cloudforce_one_scans_config.description,
  toolDefinitions.get_cloudforce_one_scans_config.inputSchema.shape,
  async ({ account_id }) => {
    const result = await client.getCloudforceOneScansConfig(account_id);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// Start server with stdio transport
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Cloudflare MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
