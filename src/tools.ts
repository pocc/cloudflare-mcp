import { z } from "zod";

// Tool definitions for Cloudflare API MCP Server
// All tools are read-only/informational

// V-005: Input length constants for SI-10 compliance
const MAX_ID_LENGTH = 64;
const MAX_EMAIL_LENGTH = 254;
const MAX_NAME_LENGTH = 253; // DNS hostname max
const MAX_IP_LENGTH = 45; // IPv6 max
const MAX_DATE_LENGTH = 30; // ISO 8601 format
const MAX_ACTION_LENGTH = 50;
const MAX_QUERY_LENGTH = 10000;
const MAX_PAGE = 10000;
const MAX_PER_PAGE = 1000;

export const toolDefinitions = {
  // ============ ACCOUNTS ============
  list_accounts: {
    name: "list_accounts",
    description: "List all Cloudflare accounts accessible with the current API token",
    inputSchema: z.object({}),
  },

  get_account: {
    name: "get_account",
    description: "Get details for a specific Cloudflare account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_account_members: {
    name: "list_account_members",
    description: "List all members of a Cloudflare account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ AUDIT LOGS ============
  get_audit_logs: {
    name: "get_audit_logs",
    description: "Get audit logs for a Cloudflare account. Returns recent activity including user actions, API calls, and configuration changes.",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      since: z.string().max(MAX_DATE_LENGTH).optional().describe("Start date in ISO 8601 format (e.g., 2024-01-01T00:00:00Z)"),
      before: z.string().max(MAX_DATE_LENGTH).optional().describe("End date in ISO 8601 format"),
      actor_email: z.string().max(MAX_EMAIL_LENGTH).optional().describe("Filter by actor email address"),
      actor_ip: z.string().max(MAX_IP_LENGTH).optional().describe("Filter by actor IP address"),
      action_type: z.string().max(MAX_ACTION_LENGTH).optional().describe("Filter by action type (e.g., 'add', 'delete', 'edit')"),
      zone_name: z.string().max(MAX_NAME_LENGTH).optional().describe("Filter by zone name"),
      per_page: z.number().max(MAX_PER_PAGE).optional().describe("Results per page (max 1000)"),
      page: z.number().max(MAX_PAGE).optional().describe("Page number"),
    }),
  },

  // ============ ZONES ============
  list_zones: {
    name: "list_zones",
    description: "List all zones (domains) in the account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).optional().describe("Filter by account ID"),
      name: z.string().max(MAX_NAME_LENGTH).optional().describe("Filter by zone name (domain)"),
      status: z.string().max(MAX_ACTION_LENGTH).optional().describe("Filter by status (active, pending, initializing, moved, deleted)"),
      per_page: z.number().max(MAX_PER_PAGE).optional().describe("Results per page"),
      page: z.number().max(MAX_PAGE).optional().describe("Page number"),
    }),
  },

  get_zone: {
    name: "get_zone",
    description: "Get details for a specific zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_zone_settings: {
    name: "get_zone_settings",
    description: "Get all settings for a zone including SSL, security, caching, and performance settings",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ SSL/TLS ============
  get_ssl_settings: {
    name: "get_ssl_settings",
    description: "Get SSL/TLS settings for a zone including encryption mode and TLS version",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_certificate_packs: {
    name: "list_certificate_packs",
    description: "List SSL certificate packs for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_ssl_verification: {
    name: "get_ssl_verification",
    description: "Get SSL verification status for a zone's certificates",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_custom_certificates: {
    name: "list_custom_certificates",
    description: "List custom SSL certificates uploaded to a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_universal_ssl_settings: {
    name: "get_universal_ssl_settings",
    description: "Get Universal SSL settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ RATE LIMITING ============
  get_rate_limiting_rules: {
    name: "get_rate_limiting_rules",
    description: "Get rate limiting rules for a zone (modern WAF rulesets API)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_legacy_rate_limits: {
    name: "list_legacy_rate_limits",
    description: "List legacy rate limiting rules for a zone (deprecated API)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ RULESETS (WAF, Firewall, etc.) ============
  list_zone_rulesets: {
    name: "list_zone_rulesets",
    description: "List all rulesets for a zone (includes WAF, rate limiting, transform rules, etc.)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_ruleset: {
    name: "get_ruleset",
    description: "Get details of a specific ruleset",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      ruleset_id: z.string().describe("The ruleset ID"),
    }),
  },

  get_waf_custom_rules: {
    name: "get_waf_custom_rules",
    description: "Get custom WAF rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_waf_managed_rules: {
    name: "get_waf_managed_rules",
    description: "Get managed WAF rules configuration for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ DNS ============
  list_dns_records: {
    name: "list_dns_records",
    description: "List DNS records for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      type: z.string().optional().describe("Filter by record type (A, AAAA, CNAME, MX, TXT, etc.)"),
      name: z.string().optional().describe("Filter by record name"),
      per_page: z.number().optional().describe("Results per page"),
    }),
  },

  // ============ FIREWALL ============
  list_firewall_rules: {
    name: "list_firewall_rules",
    description: "List firewall rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ PAGE RULES ============
  list_page_rules: {
    name: "list_page_rules",
    description: "List page rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ WORKERS ============
  list_workers: {
    name: "list_workers",
    description: "List Worker scripts in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_worker_routes: {
    name: "list_worker_routes",
    description: "List Worker routes for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ LOAD BALANCING ============
  list_load_balancers: {
    name: "list_load_balancers",
    description: "List load balancers for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_origin_pools: {
    name: "list_origin_pools",
    description: "List load balancer origin pools for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ CUSTOM HOSTNAMES (SSL for SaaS) ============
  list_custom_hostnames: {
    name: "list_custom_hostnames",
    description: "List custom hostnames (SSL for SaaS) for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      hostname: z.string().optional().describe("Filter by hostname"),
      per_page: z.number().optional().describe("Results per page"),
    }),
  },

  // ============ ACCESS (Zero Trust) ============
  list_access_apps: {
    name: "list_access_apps",
    description: "List Cloudflare Access applications for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_access_policies: {
    name: "list_access_policies",
    description: "List Cloudflare Access policies for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ BOT MANAGEMENT ============
  get_bot_management: {
    name: "get_bot_management",
    description: "Get bot management settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ ARGO ============
  get_argo_settings: {
    name: "get_argo_settings",
    description: "Get Argo Smart Routing and Tiered Caching settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ WAITING ROOM ============
  list_waiting_rooms: {
    name: "list_waiting_rooms",
    description: "List waiting rooms for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ CACHE ============
  get_cache_settings: {
    name: "get_cache_settings",
    description: "Get cache settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ ANALYTICS ============
  get_zone_analytics: {
    name: "get_zone_analytics",
    description: "Get analytics dashboard data for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      since: z.string().optional().describe("Start date in ISO 8601 format or relative (e.g., -1440 for last 24 hours in minutes)"),
      until: z.string().optional().describe("End date in ISO 8601 format"),
    }),
  },

  get_analytics_by_colo: {
    name: "get_analytics_by_colo",
    description: "Get zone analytics broken down by Cloudflare colo/data center",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      since: z.string().optional().describe("Start date"),
      until: z.string().optional().describe("End date"),
    }),
  },

  graphql_analytics: {
    name: "graphql_analytics",
    description: "Query Cloudflare Analytics using GraphQL. Supports zones, accounts, and various datasets.",
    inputSchema: z.object({
      query: z.string().max(MAX_QUERY_LENGTH).describe("GraphQL query string"),
      variables: z.string().max(MAX_QUERY_LENGTH).optional().describe("JSON string of variables for the query"),
    }),
  },

  // ============ ACCOUNT ROLES ============
  list_account_roles: {
    name: "list_account_roles",
    description: "List all roles available in a Cloudflare account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ ACCOUNT RULESETS ============
  list_account_rulesets: {
    name: "list_account_rulesets",
    description: "List all rulesets at the account level",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_account_ruleset: {
    name: "get_account_ruleset",
    description: "Get a specific account-level ruleset",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      ruleset_id: z.string().describe("The ruleset ID"),
    }),
  },

  // ============ ACCESS (Additional) ============
  list_access_groups: {
    name: "list_access_groups",
    description: "List Cloudflare Access groups for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_access_service_tokens: {
    name: "list_access_service_tokens",
    description: "List Cloudflare Access service tokens for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ WORKERS (Additional) ============
  list_worker_services: {
    name: "list_worker_services",
    description: "List Worker services in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ LOAD BALANCING (Additional) ============
  list_load_balancer_monitors: {
    name: "list_load_balancer_monitors",
    description: "List health monitors for load balancers",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ TRANSFORM RULES ============
  get_origin_rules: {
    name: "get_origin_rules",
    description: "Get origin rules for a zone (override origin server, host header, etc.)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_url_rewrite_rules: {
    name: "get_url_rewrite_rules",
    description: "Get URL rewrite/transform rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_request_header_rules: {
    name: "get_request_header_rules",
    description: "Get HTTP request header modification rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_response_header_rules: {
    name: "get_response_header_rules",
    description: "Get HTTP response header modification rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ CACHE RULES ============
  get_cache_rules: {
    name: "get_cache_rules",
    description: "Get cache rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ DDOS ============
  get_ddos_l7_rules: {
    name: "get_ddos_l7_rules",
    description: "Get Layer 7 DDoS protection rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_ddos_l4_rules: {
    name: "get_ddos_l4_rules",
    description: "Get Layer 4 DDoS protection rules for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ SPECTRUM ============
  list_spectrum_apps: {
    name: "list_spectrum_apps",
    description: "List Spectrum applications for a zone (TCP/UDP proxy)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ API SHIELD ============
  list_api_shield_operations: {
    name: "list_api_shield_operations",
    description: "List API Shield operations/endpoints for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_api_shield_schemas: {
    name: "list_api_shield_schemas",
    description: "List API Shield schemas for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_api_shield_config: {
    name: "get_api_shield_config",
    description: "Get API Shield configuration for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ D1 DATABASES ============
  list_d1_databases: {
    name: "list_d1_databases",
    description: "List D1 SQL databases in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_d1_database: {
    name: "get_d1_database",
    description: "Get details of a D1 database",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      database_id: z.string().describe("The D1 database ID"),
    }),
  },

  // ============ R2 STORAGE ============
  list_r2_buckets: {
    name: "list_r2_buckets",
    description: "List R2 storage buckets in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ KV NAMESPACES ============
  list_kv_namespaces: {
    name: "list_kv_namespaces",
    description: "List Workers KV namespaces in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_kv_namespace: {
    name: "get_kv_namespace",
    description: "Get details of a KV namespace",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      namespace_id: z.string().describe("The KV namespace ID"),
    }),
  },

  list_kv_keys: {
    name: "list_kv_keys",
    description: "List keys in a KV namespace",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      namespace_id: z.string().describe("The KV namespace ID"),
      prefix: z.string().optional().describe("Filter keys by prefix"),
      limit: z.number().optional().describe("Maximum keys to return"),
    }),
  },

  // ============ DURABLE OBJECTS ============
  list_durable_object_namespaces: {
    name: "list_durable_object_namespaces",
    description: "List Durable Object namespaces in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ QUEUES ============
  list_queues: {
    name: "list_queues",
    description: "List Cloudflare Queues in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_queue: {
    name: "get_queue",
    description: "Get details of a Cloudflare Queue",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      queue_id: z.string().describe("The queue ID"),
    }),
  },

  // ============ TUNNELS ============
  list_tunnels: {
    name: "list_tunnels",
    description: "List Cloudflare Tunnels in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_tunnel: {
    name: "get_tunnel",
    description: "Get details of a Cloudflare Tunnel",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      tunnel_id: z.string().describe("The tunnel ID"),
    }),
  },

  list_tunnel_connections: {
    name: "list_tunnel_connections",
    description: "List active connections for a Cloudflare Tunnel",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      tunnel_id: z.string().describe("The tunnel ID"),
    }),
  },

  // ============ LOGPUSH ============
  list_logpush_jobs_zone: {
    name: "list_logpush_jobs_zone",
    description: "List Logpush jobs for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_logpush_jobs_account: {
    name: "list_logpush_jobs_account",
    description: "List Logpush jobs for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ EMAIL ROUTING ============
  get_email_routing_settings: {
    name: "get_email_routing_settings",
    description: "Get email routing settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_email_routing_rules: {
    name: "list_email_routing_rules",
    description: "List email routing rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_email_routing_addresses: {
    name: "list_email_routing_addresses",
    description: "List verified destination email addresses",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ PAGES ============
  list_pages_projects: {
    name: "list_pages_projects",
    description: "List Cloudflare Pages projects in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_pages_project: {
    name: "get_pages_project",
    description: "Get details of a Pages project",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      project_name: z.string().describe("The project name"),
    }),
  },

  list_pages_deployments: {
    name: "list_pages_deployments",
    description: "List deployments for a Pages project",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      project_name: z.string().describe("The project name"),
    }),
  },

  // ============ STREAM ============
  list_stream_videos: {
    name: "list_stream_videos",
    description: "List videos in Cloudflare Stream",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_stream_video: {
    name: "get_stream_video",
    description: "Get details of a Stream video",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      video_id: z.string().describe("The video ID"),
    }),
  },

  // ============ IMAGES ============
  list_images: {
    name: "list_images",
    description: "List images in Cloudflare Images",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_images_stats: {
    name: "get_images_stats",
    description: "Get Cloudflare Images usage statistics",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ REGISTRAR ============
  list_registrar_domains: {
    name: "list_registrar_domains",
    description: "List domains registered with Cloudflare Registrar",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_registrar_domain: {
    name: "get_registrar_domain",
    description: "Get details of a domain in Cloudflare Registrar",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      domain_name: z.string().describe("The domain name"),
    }),
  },

  // ============ HEALTHCHECKS ============
  list_healthchecks: {
    name: "list_healthchecks",
    description: "List healthchecks for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_healthcheck: {
    name: "get_healthcheck",
    description: "Get details of a healthcheck",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      healthcheck_id: z.string().describe("The healthcheck ID"),
    }),
  },

  // ============ IP ACCESS RULES ============
  list_ip_access_rules: {
    name: "list_ip_access_rules",
    description: "List IP access rules for a zone (IP blocking/allowing)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ ZONE LOCKDOWN ============
  list_zone_lockdown_rules: {
    name: "list_zone_lockdown_rules",
    description: "List zone lockdown rules (IP allowlisting for URLs)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ USER AGENT RULES ============
  list_user_agent_rules: {
    name: "list_user_agent_rules",
    description: "List user agent blocking rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ ORIGIN CA ============
  list_origin_ca_certificates: {
    name: "list_origin_ca_certificates",
    description: "List Origin CA certificates for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ CLIENT CERTIFICATES (mTLS) ============
  list_client_certificates: {
    name: "list_client_certificates",
    description: "List client certificates for mTLS",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ AUTHENTICATED ORIGIN PULLS ============
  get_authenticated_origin_pulls: {
    name: "get_authenticated_origin_pulls",
    description: "Get Authenticated Origin Pulls settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ FILTERS ============
  list_filters: {
    name: "list_filters",
    description: "List filters used by firewall rules",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ SNIPPETS ============
  list_snippets: {
    name: "list_snippets",
    description: "List Cloudflare Snippets for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ WEB3 HOSTNAMES ============
  list_web3_hostnames: {
    name: "list_web3_hostnames",
    description: "List Web3 hostnames for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ ZARAZ ============
  get_zaraz_config: {
    name: "get_zaraz_config",
    description: "Get Zaraz configuration for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ MISSING INDIVIDUAL GET ENDPOINTS ============
  get_zone_setting: {
    name: "get_zone_setting",
    description: "Get a specific zone setting by name (e.g., ssl, min_tls_version, security_level)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      setting_name: z.string().describe("The setting name (e.g., ssl, min_tls_version, tls_1_3, security_level, waf)"),
    }),
  },

  get_certificate_pack: {
    name: "get_certificate_pack",
    description: "Get details of a specific SSL certificate pack",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      certificate_pack_id: z.string().describe("The certificate pack ID"),
    }),
  },

  get_custom_certificate: {
    name: "get_custom_certificate",
    description: "Get details of a specific custom SSL certificate",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      certificate_id: z.string().describe("The custom certificate ID"),
    }),
  },

  get_legacy_rate_limit: {
    name: "get_legacy_rate_limit",
    description: "Get details of a specific legacy rate limit rule",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      rate_limit_id: z.string().describe("The rate limit rule ID"),
    }),
  },

  get_dns_record: {
    name: "get_dns_record",
    description: "Get details of a specific DNS record",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      dns_record_id: z.string().describe("The DNS record ID"),
    }),
  },

  get_page_rule: {
    name: "get_page_rule",
    description: "Get details of a specific page rule",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      pagerule_id: z.string().describe("The page rule ID"),
    }),
  },

  get_worker_script: {
    name: "get_worker_script",
    description: "Get metadata for a specific Worker script",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      script_name: z.string().describe("The Worker script name"),
    }),
  },

  get_custom_hostname: {
    name: "get_custom_hostname",
    description: "Get details of a specific custom hostname",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      custom_hostname_id: z.string().describe("The custom hostname ID"),
    }),
  },

  get_waiting_room: {
    name: "get_waiting_room",
    description: "Get details of a specific waiting room",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      waiting_room_id: z.string().describe("The waiting room ID"),
    }),
  },

  // ============ WORKERS AI ============
  list_ai_models: {
    name: "list_ai_models",
    description: "List available Workers AI models",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ VECTORIZE ============
  list_vectorize_indexes: {
    name: "list_vectorize_indexes",
    description: "List Vectorize indexes (vector databases) in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_vectorize_index: {
    name: "get_vectorize_index",
    description: "Get details of a Vectorize index",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      index_name: z.string().describe("The Vectorize index name"),
    }),
  },

  // ============ AI GATEWAY ============
  list_ai_gateways: {
    name: "list_ai_gateways",
    description: "List AI Gateway instances in an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_ai_gateway_logs: {
    name: "get_ai_gateway_logs",
    description: "Get logs for an AI Gateway",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
    }),
  },

  // ============ WORKERS SECRETS ============
  list_worker_secrets: {
    name: "list_worker_secrets",
    description: "List secret names for a Worker script (does not return secret values)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      script_name: z.string().describe("The Worker script name"),
    }),
  },

  // ============ WORKERS DEPLOYMENTS ============
  list_worker_deployments: {
    name: "list_worker_deployments",
    description: "List deployments for a Worker script (useful for rollback decisions)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      script_name: z.string().describe("The Worker script name"),
    }),
  },

  // ============ WORKERS TAIL LOGS ============
  list_worker_tails: {
    name: "list_worker_tails",
    description: "List active tail log sessions for a Worker script",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      script_name: z.string().describe("The Worker script name"),
    }),
  },

  // ============ USER ============
  get_user: {
    name: "get_user",
    description: "Get current authenticated user details (email, ID, etc.)",
    inputSchema: z.object({}),
  },

  verify_token: {
    name: "verify_token",
    description: "Verify the current API token and get its status",
    inputSchema: z.object({}),
  },

  // ============ BILLING ============
  get_billing_profile: {
    name: "get_billing_profile",
    description: "Get billing profile for an account (payment status, etc.)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ ZONE SUBSCRIPTION ============
  get_zone_subscription: {
    name: "get_zone_subscription",
    description: "Get zone subscription tier (Free/Pro/Business/Enterprise) - determines available features",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ DEVICES (ZERO TRUST) ============
  list_devices: {
    name: "list_devices",
    description: "List devices enrolled in Zero Trust/WARP",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_device_posture_rules: {
    name: "list_device_posture_rules",
    description: "List device posture rules (compliance requirements)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_device_policies: {
    name: "list_device_policies",
    description: "List device policies for Zero Trust",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ DNSSEC ============
  get_dnssec: {
    name: "get_dnssec",
    description: "Get DNSSEC status for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ PURGE CACHE ============
  get_cache_purge_status: {
    name: "get_cache_purge_status",
    description: "Get information about zone's cache status (note: purge is a POST action, this tool provides cache-related info)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ PAGE SHIELD ============
  get_page_shield_settings: {
    name: "get_page_shield_settings",
    description: "Get Page Shield settings for a zone (client-side security monitoring)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_page_shield_scripts: {
    name: "list_page_shield_scripts",
    description: "List scripts detected by Page Shield",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_page_shield_connections: {
    name: "list_page_shield_connections",
    description: "List connections detected by Page Shield",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_page_shield_policies: {
    name: "list_page_shield_policies",
    description: "List Page Shield policies",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ SECURITY CENTER ============
  list_security_insights: {
    name: "list_security_insights",
    description: "List Security Center insights for a zone (security issues and recommendations)",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ ALERTING/NOTIFICATIONS ============
  list_notification_policies: {
    name: "list_notification_policies",
    description: "List notification/alerting policies for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_notification_history: {
    name: "list_notification_history",
    description: "List notification history (past alerts sent)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_available_alerts: {
    name: "list_available_alerts",
    description: "List available alert types that can be configured",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_notification_webhooks: {
    name: "list_notification_webhooks",
    description: "List configured notification webhook destinations",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ TUNNEL CONFIGURATIONS ============
  get_tunnel_configuration: {
    name: "get_tunnel_configuration",
    description: "Get configuration for a Cloudflare Tunnel (ingress rules, etc.)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      tunnel_id: z.string().describe("The tunnel ID"),
    }),
  },

  // ============ TURNSTILE (CHALLENGES) ============
  list_turnstile_widgets: {
    name: "list_turnstile_widgets",
    description: "List Turnstile widgets (CAPTCHA alternatives) for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_turnstile_widget: {
    name: "get_turnstile_widget",
    description: "Get details of a specific Turnstile widget",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      widget_id: z.string().describe("The Turnstile widget sitekey"),
    }),
  },

  // ============ GATEWAY (ZERO TRUST) ============
  list_gateway_rules: {
    name: "list_gateway_rules",
    description: "List Zero Trust Gateway rules (DNS/HTTP/Network filtering)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_gateway_configuration: {
    name: "get_gateway_configuration",
    description: "Get Zero Trust Gateway configuration settings",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_gateway_locations: {
    name: "list_gateway_locations",
    description: "List Gateway locations (DNS resolver endpoints)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  list_gateway_proxy_endpoints: {
    name: "list_gateway_proxy_endpoints",
    description: "List Gateway proxy endpoints",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  // ============ HYPERDRIVE ============
  list_hyperdrive_configs: {
    name: "list_hyperdrive_configs",
    description: "List Hyperdrive configurations (database connection accelerators)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_hyperdrive_config: {
    name: "get_hyperdrive_config",
    description: "Get details of a Hyperdrive configuration",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      hyperdrive_id: z.string().describe("The Hyperdrive configuration ID"),
    }),
  },

  // ============ URL NORMALIZATION ============
  get_url_normalization: {
    name: "get_url_normalization",
    description: "Get URL normalization settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ MANAGED HEADERS ============
  get_managed_headers: {
    name: "get_managed_headers",
    description: "Get managed request/response headers configuration",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ KEYLESS SSL ============
  list_keyless_certificates: {
    name: "list_keyless_certificates",
    description: "List Keyless SSL certificates for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  // ============ MAGIC TRANSIT ============
  list_magic_transit_ipsec_tunnels: {
    name: "list_magic_transit_ipsec_tunnels",
    description: "List Magic Transit IPsec tunnels for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_magic_transit_ipsec_tunnel: {
    name: "get_magic_transit_ipsec_tunnel",
    description: "Get details of a specific Magic Transit IPsec tunnel",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      tunnel_id: z.string().describe("The IPsec tunnel ID"),
    }),
  },

  list_magic_transit_gre_tunnels: {
    name: "list_magic_transit_gre_tunnels",
    description: "List Magic Transit GRE tunnels for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_magic_transit_gre_tunnel: {
    name: "get_magic_transit_gre_tunnel",
    description: "Get details of a specific Magic Transit GRE tunnel",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      tunnel_id: z.string().describe("The GRE tunnel ID"),
    }),
  },

  list_magic_transit_routes: {
    name: "list_magic_transit_routes",
    description: "List Magic Transit static routes for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_magic_transit_route: {
    name: "get_magic_transit_route",
    description: "Get details of a specific Magic Transit static route",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      route_id: z.string().describe("The route ID"),
    }),
  },

  list_magic_transit_connectors: {
    name: "list_magic_transit_connectors",
    description: "List Magic Transit connectors for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_magic_transit_connector: {
    name: "get_magic_transit_connector",
    description: "Get details of a specific Magic Transit connector",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      connector_id: z.string().describe("The connector ID"),
    }),
  },

  list_magic_transit_sites: {
    name: "list_magic_transit_sites",
    description: "List Magic WAN sites for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_magic_transit_site: {
    name: "get_magic_transit_site",
    description: "Get details of a specific Magic WAN site",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      site_id: z.string().describe("The site ID"),
    }),
  },

  // ============ DNS FIREWALL ============
  list_dns_firewall_clusters: {
    name: "list_dns_firewall_clusters",
    description: "List DNS Firewall clusters for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_dns_firewall_cluster: {
    name: "get_dns_firewall_cluster",
    description: "Get details of a specific DNS Firewall cluster",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      cluster_id: z.string().describe("The DNS Firewall cluster ID"),
    }),
  },

  get_dns_firewall_analytics: {
    name: "get_dns_firewall_analytics",
    description: "Get DNS Firewall analytics for a cluster",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      cluster_id: z.string().describe("The DNS Firewall cluster ID"),
    }),
  },

  // ============ SECONDARY DNS ============
  get_secondary_dns_primary: {
    name: "get_secondary_dns_primary",
    description: "Get secondary DNS primary nameserver configuration for a zone",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_secondary_dns_peers: {
    name: "list_secondary_dns_peers",
    description: "List secondary DNS peers for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_secondary_dns_peer: {
    name: "get_secondary_dns_peer",
    description: "Get details of a specific secondary DNS peer",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      peer_id: z.string().describe("The peer ID"),
    }),
  },

  list_secondary_dns_tsigs: {
    name: "list_secondary_dns_tsigs",
    description: "List secondary DNS TSIG keys for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_secondary_dns_tsig: {
    name: "get_secondary_dns_tsig",
    description: "Get details of a specific secondary DNS TSIG key",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      tsig_id: z.string().describe("The TSIG key ID"),
    }),
  },

  get_secondary_dns_incoming: {
    name: "get_secondary_dns_incoming",
    description: "Get secondary DNS incoming zone transfer configuration",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_secondary_dns_outgoing: {
    name: "get_secondary_dns_outgoing",
    description: "Get secondary DNS outgoing zone transfer configuration",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  list_secondary_dns_acls: {
    name: "list_secondary_dns_acls",
    description: "List secondary DNS ACLs for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_secondary_dns_acl: {
    name: "get_secondary_dns_acl",
    description: "Get details of a specific secondary DNS ACL",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      acl_id: z.string().describe("The ACL ID"),
    }),
  },

  // ============ SPEED API ============
  list_speed_tests: {
    name: "list_speed_tests",
    description: "List speed tests for a zone URL",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      url: z.string().describe("URL to get speed tests for"),
    }),
  },

  get_speed_test: {
    name: "get_speed_test",
    description: "Get details of a specific speed test",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      url: z.string().describe("URL the test was run for"),
      test_id: z.string().describe("The speed test ID"),
    }),
  },

  get_speed_schedule: {
    name: "get_speed_schedule",
    description: "Get scheduled speed test configuration for a URL",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      url: z.string().describe("URL to get schedule for"),
    }),
  },

  list_speed_available_regions: {
    name: "list_speed_available_regions",
    description: "List available regions for speed tests",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
    }),
  },

  get_speed_page_trend: {
    name: "get_speed_page_trend",
    description: "Get speed trends for a page over time",
    inputSchema: z.object({
      zone_id: z.string().max(MAX_ID_LENGTH).describe("The zone ID"),
      url: z.string().describe("URL to get trends for"),
    }),
  },

  // ============ CALLS (WebRTC) ============
  list_calls_apps: {
    name: "list_calls_apps",
    description: "List Cloudflare Calls applications (WebRTC)",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_calls_app: {
    name: "get_calls_app",
    description: "Get details of a specific Calls application",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      app_id: z.string().describe("The Calls application ID"),
    }),
  },

  list_calls_turn_keys: {
    name: "list_calls_turn_keys",
    description: "List TURN keys for Cloudflare Calls",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_calls_turn_key: {
    name: "get_calls_turn_key",
    description: "Get details of a specific TURN key",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      key_id: z.string().describe("The TURN key ID"),
    }),
  },

  // ============ DLP (Data Loss Prevention) ============
  list_dlp_profiles: {
    name: "list_dlp_profiles",
    description: "List DLP profiles for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_dlp_profile: {
    name: "get_dlp_profile",
    description: "Get details of a specific DLP profile",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      profile_id: z.string().describe("The DLP profile ID"),
    }),
  },

  list_dlp_datasets: {
    name: "list_dlp_datasets",
    description: "List DLP datasets for an account",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_dlp_dataset: {
    name: "get_dlp_dataset",
    description: "Get details of a specific DLP dataset",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
      dataset_id: z.string().describe("The DLP dataset ID"),
    }),
  },

  list_dlp_patterns: {
    name: "list_dlp_patterns",
    description: "List predefined DLP patterns available",
    inputSchema: z.object({
      account_id: z.string().max(MAX_ID_LENGTH).describe("The account ID"),
    }),
  },

  get_dlp_payload_log_settings: {
    name: "get_dlp_payload_log_settings",
    description: "Get DLP payload logging settings for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ CLOUDFLARE IPS ============
  get_cloudflare_ips: {
    name: "get_cloudflare_ips",
    description: "Get Cloudflare's IP ranges (IPv4 and IPv6) - useful for allowlisting",
    inputSchema: z.object({}),
  },

  // ============ MEMBERSHIPS ============
  list_memberships: {
    name: "list_memberships",
    description: "List account memberships for the authenticated user",
    inputSchema: z.object({}),
  },

  get_membership: {
    name: "get_membership",
    description: "Get details of a specific account membership",
    inputSchema: z.object({
      membership_id: z.string().describe("The membership ID"),
    }),
  },

  // ============ ACCESS (EXTENDED) ============
  list_access_bookmarks: {
    name: "list_access_bookmarks",
    description: "List Access bookmarks for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_access_bookmark: {
    name: "get_access_bookmark",
    description: "Get details of an Access bookmark",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      bookmark_id: z.string().describe("The bookmark ID"),
    }),
  },

  list_access_certificates: {
    name: "list_access_certificates",
    description: "List Access mTLS certificates for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_access_certificate: {
    name: "get_access_certificate",
    description: "Get details of an Access mTLS certificate",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      certificate_id: z.string().describe("The certificate ID"),
    }),
  },

  get_access_certificate_settings: {
    name: "get_access_certificate_settings",
    description: "Get Access mTLS certificate settings",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_access_custom_pages: {
    name: "list_access_custom_pages",
    description: "List Access custom pages for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_access_custom_page: {
    name: "get_access_custom_page",
    description: "Get details of an Access custom page",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      custom_page_id: z.string().describe("The custom page ID"),
    }),
  },

  list_access_identity_providers: {
    name: "list_access_identity_providers",
    description: "List Access identity providers for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_access_identity_provider: {
    name: "get_access_identity_provider",
    description: "Get details of an Access identity provider",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      identity_provider_id: z.string().describe("The identity provider ID"),
    }),
  },

  get_access_keys: {
    name: "get_access_keys",
    description: "Get Access keys configuration (signing keys for tokens)",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_access_logs: {
    name: "list_access_logs",
    description: "List Access request logs for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_access_organization: {
    name: "get_access_organization",
    description: "Get Access organization settings for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_access_tags: {
    name: "list_access_tags",
    description: "List Access tags for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_access_tag: {
    name: "get_access_tag",
    description: "Get details of an Access tag",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      tag_name: z.string().describe("The tag name"),
    }),
  },

  list_access_users: {
    name: "list_access_users",
    description: "List Access users for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_access_user_active_sessions: {
    name: "list_access_user_active_sessions",
    description: "List active sessions for an Access user",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      user_id: z.string().describe("The user ID"),
    }),
  },

  list_access_user_failed_logins: {
    name: "list_access_user_failed_logins",
    description: "List failed logins for an Access user",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      user_id: z.string().describe("The user ID"),
    }),
  },

  // ============ AI GATEWAY (EXTENDED) ============
  list_ai_gateway_datasets: {
    name: "list_ai_gateway_datasets",
    description: "List datasets for an AI Gateway",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
    }),
  },

  get_ai_gateway_dataset: {
    name: "get_ai_gateway_dataset",
    description: "Get details of an AI Gateway dataset",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
      dataset_id: z.string().describe("The dataset ID"),
    }),
  },

  list_ai_gateway_evaluations: {
    name: "list_ai_gateway_evaluations",
    description: "List evaluations for an AI Gateway",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
    }),
  },

  get_ai_gateway_evaluation: {
    name: "get_ai_gateway_evaluation",
    description: "Get details of an AI Gateway evaluation",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
      evaluation_id: z.string().describe("The evaluation ID"),
    }),
  },

  list_ai_gateway_routes: {
    name: "list_ai_gateway_routes",
    description: "List routes for an AI Gateway",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
    }),
  },

  get_ai_gateway_route: {
    name: "get_ai_gateway_route",
    description: "Get details of an AI Gateway route",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      gateway_id: z.string().describe("The AI Gateway ID"),
      route_id: z.string().describe("The route ID"),
    }),
  },

  // ============ IP ADDRESSING (BYOIP) ============
  list_address_maps: {
    name: "list_address_maps",
    description: "List IP address maps for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_address_map: {
    name: "get_address_map",
    description: "Get details of an IP address map",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      address_map_id: z.string().describe("The address map ID"),
    }),
  },

  list_ip_prefixes: {
    name: "list_ip_prefixes",
    description: "List IP prefixes (BYOIP) for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_ip_prefix: {
    name: "get_ip_prefix",
    description: "Get details of an IP prefix",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      prefix_id: z.string().describe("The prefix ID"),
    }),
  },

  get_ip_prefix_bgp_status: {
    name: "get_ip_prefix_bgp_status",
    description: "Get BGP status for an IP prefix",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      prefix_id: z.string().describe("The prefix ID"),
    }),
  },

  list_ip_prefix_delegations: {
    name: "list_ip_prefix_delegations",
    description: "List delegations for an IP prefix",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      prefix_id: z.string().describe("The prefix ID"),
    }),
  },

  list_addressing_services: {
    name: "list_addressing_services",
    description: "List addressing services for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ URL SCANNER ============
  get_url_scan: {
    name: "get_url_scan",
    description: "Get URL scan result",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      scan_id: z.string().describe("The scan ID"),
    }),
  },

  get_url_scan_har: {
    name: "get_url_scan_har",
    description: "Get HAR file from URL scan",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      scan_id: z.string().describe("The scan ID"),
    }),
  },

  // ============ AI SEARCH ============
  list_ai_search_instances: {
    name: "list_ai_search_instances",
    description: "List AI Search instances for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_ai_search_instance: {
    name: "get_ai_search_instance",
    description: "Get details of an AI Search instance",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      instance_id: z.string().describe("The instance ID"),
    }),
  },

  list_ai_search_items: {
    name: "list_ai_search_items",
    description: "List items in an AI Search instance",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      instance_id: z.string().describe("The instance ID"),
    }),
  },

  list_ai_search_jobs: {
    name: "list_ai_search_jobs",
    description: "List jobs for an AI Search instance",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      instance_id: z.string().describe("The instance ID"),
    }),
  },

  get_ai_search_job: {
    name: "get_ai_search_job",
    description: "Get details of an AI Search job",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      instance_id: z.string().describe("The instance ID"),
      job_id: z.string().describe("The job ID"),
    }),
  },

  // ============ WORKERS BUILDS ============
  list_worker_builds: {
    name: "list_worker_builds",
    description: "List Worker builds for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_worker_build: {
    name: "get_worker_build",
    description: "Get details of a Worker build",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      build_id: z.string().describe("The build ID"),
    }),
  },

  // ============ WORKERS WORKFLOWS ============
  list_workflows: {
    name: "list_workflows",
    description: "List Workers Workflows for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_workflow: {
    name: "get_workflow",
    description: "Get details of a Workers Workflow",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      workflow_name: z.string().describe("The workflow name"),
    }),
  },

  list_workflow_instances: {
    name: "list_workflow_instances",
    description: "List instances of a Workers Workflow",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      workflow_name: z.string().describe("The workflow name"),
    }),
  },

  get_workflow_instance: {
    name: "get_workflow_instance",
    description: "Get details of a workflow instance",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      workflow_name: z.string().describe("The workflow name"),
      instance_id: z.string().describe("The instance ID"),
    }),
  },

  // ============ CNI (INTERCONNECT) ============
  list_cni_interconnects: {
    name: "list_cni_interconnects",
    description: "List Cloud Network Interconnects for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_cni_interconnect: {
    name: "get_cni_interconnect",
    description: "Get details of a Cloud Network Interconnect",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      interconnect_id: z.string().describe("The interconnect ID"),
    }),
  },

  list_cni_slots: {
    name: "list_cni_slots",
    description: "List CNI slots for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_cni_settings: {
    name: "get_cni_settings",
    description: "Get CNI settings for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ R2 PIPELINES ============
  list_r2_pipelines: {
    name: "list_r2_pipelines",
    description: "List R2 pipelines for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_r2_pipeline: {
    name: "get_r2_pipeline",
    description: "Get details of an R2 pipeline",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      pipeline_name: z.string().describe("The pipeline name"),
    }),
  },

  // ============ IAM/PERMISSIONS ============
  list_permission_groups: {
    name: "list_permission_groups",
    description: "List IAM permission groups for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_permission_group: {
    name: "get_permission_group",
    description: "Get details of an IAM permission group",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      group_id: z.string().describe("The permission group ID"),
    }),
  },

  list_resource_groups: {
    name: "list_resource_groups",
    description: "List IAM resource groups for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_resource_group: {
    name: "get_resource_group",
    description: "Get details of an IAM resource group",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      group_id: z.string().describe("The resource group ID"),
    }),
  },

  // ============ ZERO TRUST RISK SCORING ============
  list_risk_scoring_behaviors: {
    name: "list_risk_scoring_behaviors",
    description: "List Zero Trust risk scoring behaviors",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_risk_scoring_integrations: {
    name: "list_risk_scoring_integrations",
    description: "List Zero Trust risk scoring integrations",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_risk_scoring_integration: {
    name: "get_risk_scoring_integration",
    description: "Get details of a risk scoring integration",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      integration_id: z.string().describe("The integration ID"),
    }),
  },

  // ============ R2 CATALOG ============
  list_r2_catalogs: {
    name: "list_r2_catalogs",
    description: "List R2 catalogs for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_r2_catalog: {
    name: "get_r2_catalog",
    description: "Get details of an R2 catalog",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      catalog_name: z.string().describe("The catalog name"),
    }),
  },

  // ============ TEAM NETWORK ROUTES ============
  list_teamnet_routes: {
    name: "list_teamnet_routes",
    description: "List team network routes for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_teamnet_virtual_networks: {
    name: "list_teamnet_virtual_networks",
    description: "List team virtual networks for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_teamnet_virtual_network: {
    name: "get_teamnet_virtual_network",
    description: "Get details of a team virtual network",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      vnet_id: z.string().describe("The virtual network ID"),
    }),
  },

  // ============ SECRETS STORE ============
  list_secrets_stores: {
    name: "list_secrets_stores",
    description: "List secrets stores for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_secrets_store: {
    name: "get_secrets_store",
    description: "Get details of a secrets store",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      store_id: z.string().describe("The store ID"),
    }),
  },

  list_secrets_store_secrets: {
    name: "list_secrets_store_secrets",
    description: "List secrets in a secrets store (names only)",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      store_id: z.string().describe("The store ID"),
    }),
  },

  // ============ PACKET CAPTURES ============
  list_pcaps: {
    name: "list_pcaps",
    description: "List packet captures for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_pcap: {
    name: "get_pcap",
    description: "Get details of a packet capture",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      pcap_id: z.string().describe("The packet capture ID"),
    }),
  },

  get_pcap_ownership: {
    name: "get_pcap_ownership",
    description: "Get packet capture ownership info",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ MAGIC NETWORK MONITORING ============
  get_mnm_config: {
    name: "get_mnm_config",
    description: "Get Magic Network Monitoring configuration",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_mnm_rules: {
    name: "list_mnm_rules",
    description: "List Magic Network Monitoring rules",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_mnm_rule: {
    name: "get_mnm_rule",
    description: "Get details of a Magic Network Monitoring rule",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      rule_id: z.string().describe("The rule ID"),
    }),
  },

  // ============ WARP CONNECTOR ============
  list_warp_connectors: {
    name: "list_warp_connectors",
    description: "List WARP connectors for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_warp_connector: {
    name: "get_warp_connector",
    description: "Get details of a WARP connector",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      connector_id: z.string().describe("The connector ID"),
    }),
  },

  // ============ MTLS CERTIFICATES (ACCOUNT) ============
  list_account_mtls_certificates: {
    name: "list_account_mtls_certificates",
    description: "List mTLS certificates at account level",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_account_mtls_certificate: {
    name: "get_account_mtls_certificate",
    description: "Get details of an account mTLS certificate",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      certificate_id: z.string().describe("The certificate ID"),
    }),
  },

  // ============ ACCOUNT DNS SETTINGS ============
  get_account_dns_settings: {
    name: "get_account_dns_settings",
    description: "Get DNS settings for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_dns_views: {
    name: "list_dns_views",
    description: "List DNS views for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dns_view: {
    name: "get_dns_view",
    description: "Get details of a DNS view",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      view_id: z.string().describe("The view ID"),
    }),
  },

  // ============ ZONE: API SCHEMA VALIDATION ============
  get_schema_validation_settings: {
    name: "get_schema_validation_settings",
    description: "Get API schema validation settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  list_api_schemas: {
    name: "list_api_schemas",
    description: "List API schemas for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: TOKEN VALIDATION ============
  get_token_validation_settings: {
    name: "get_token_validation_settings",
    description: "Get token validation settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: SMART SHIELD ============
  get_smart_shield_settings: {
    name: "get_smart_shield_settings",
    description: "Get Smart Shield settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: LOGS ============
  get_zone_logs_retention: {
    name: "get_zone_logs_retention",
    description: "Get zone logs retention settings",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: LEAKED CREDENTIAL CHECKS ============
  get_leaked_credential_check_settings: {
    name: "get_leaked_credential_check_settings",
    description: "Get leaked credential check settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  list_leaked_credential_detections: {
    name: "list_leaked_credential_detections",
    description: "List leaked credential detections for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: ADVANCED CERTIFICATE MANAGER ============
  get_total_tls_settings: {
    name: "get_total_tls_settings",
    description: "Get Total TLS settings for a zone (Advanced Certificate Manager)",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: DNS ANALYTICS ============
  get_dns_analytics_report: {
    name: "get_dns_analytics_report",
    description: "Get DNS analytics report for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: FRAUD DETECTION ============
  get_fraud_detection_settings: {
    name: "get_fraud_detection_settings",
    description: "Get fraud detection settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: CLOUD CONNECTOR ============
  list_cloud_connector_rules: {
    name: "list_cloud_connector_rules",
    description: "List cloud connector rules for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: DCV DELEGATION ============
  get_dcv_delegation: {
    name: "get_dcv_delegation",
    description: "Get DCV delegation UUID for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ INTEL ============
  get_intel_asn: {
    name: "get_intel_asn",
    description: "Get intelligence about an ASN",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      asn: z.number().describe("The ASN number"),
    }),
  },

  get_intel_domain: {
    name: "get_intel_domain",
    description: "Get intelligence about a domain",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      domain: z.string().optional().describe("Domain to query"),
    }),
  },

  get_intel_domain_history: {
    name: "get_intel_domain_history",
    description: "Get domain history intelligence",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_intel_ip: {
    name: "get_intel_ip",
    description: "Get intelligence about an IP address",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      ipv4: z.string().optional().describe("IPv4 address to query"),
      ipv6: z.string().optional().describe("IPv6 address to query"),
    }),
  },

  get_intel_whois: {
    name: "get_intel_whois",
    description: "Get WHOIS information for a domain",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      domain: z.string().optional().describe("Domain to query"),
    }),
  },

  list_intel_indicator_feeds: {
    name: "list_intel_indicator_feeds",
    description: "List threat indicator feeds",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_intel_indicator_feed: {
    name: "get_intel_indicator_feed",
    description: "Get details of a threat indicator feed",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      feed_id: z.number().describe("The feed ID"),
    }),
  },

  list_intel_sinkholes: {
    name: "list_intel_sinkholes",
    description: "List Cloudflare sinkholes",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_intel_ip_lists: {
    name: "list_intel_ip_lists",
    description: "List IP lists for threat intelligence",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ RULES/LISTS ============
  list_account_rules_lists: {
    name: "list_account_rules_lists",
    description: "List account-level rules lists (IP lists, hostname lists, etc.)",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_account_rules_list: {
    name: "get_account_rules_list",
    description: "Get details of an account rules list",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      list_id: z.string().describe("The list ID"),
    }),
  },

  list_account_rules_list_items: {
    name: "list_account_rules_list_items",
    description: "List items in an account rules list",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      list_id: z.string().describe("The list ID"),
    }),
  },

  // ============ API TOKENS ============
  list_account_tokens: {
    name: "list_account_tokens",
    description: "List API tokens for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_account_token: {
    name: "get_account_token",
    description: "Get details of an API token",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      token_id: z.string().describe("The token ID"),
    }),
  },

  verify_account_token: {
    name: "verify_account_token",
    description: "Verify an API token is valid",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_token_permission_groups: {
    name: "list_token_permission_groups",
    description: "List available permission groups for API tokens",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ RUM (Real User Monitoring) ============
  list_rum_sites: {
    name: "list_rum_sites",
    description: "List Real User Monitoring sites",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_rum_site: {
    name: "get_rum_site",
    description: "Get details of a RUM site",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      site_id: z.string().describe("The site ID"),
    }),
  },

  // ============ ABUSE REPORTS ============
  list_abuse_reports: {
    name: "list_abuse_reports",
    description: "List abuse reports for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_abuse_report: {
    name: "get_abuse_report",
    description: "Get details of an abuse report",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      report_id: z.string().describe("The report ID"),
    }),
  },

  // ============ INFRASTRUCTURE TARGETS ============
  list_infrastructure_targets: {
    name: "list_infrastructure_targets",
    description: "List infrastructure targets",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_infrastructure_target: {
    name: "get_infrastructure_target",
    description: "Get details of an infrastructure target",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      target_id: z.string().describe("The target ID"),
    }),
  },

  // ============ CONNECTIVITY SERVICES ============
  list_connectivity_services: {
    name: "list_connectivity_services",
    description: "List connectivity directory services",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_connectivity_service: {
    name: "get_connectivity_service",
    description: "Get details of a connectivity service",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      service_id: z.string().describe("The service ID"),
    }),
  },

  // ============ DIAGNOSTICS ============
  list_endpoint_healthchecks: {
    name: "list_endpoint_healthchecks",
    description: "List endpoint healthchecks for diagnostics",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_endpoint_healthcheck: {
    name: "get_endpoint_healthcheck",
    description: "Get details of an endpoint healthcheck",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      healthcheck_id: z.string().describe("The healthcheck ID"),
    }),
  },

  // ============ CONTAINERS ============
  list_containers: {
    name: "list_containers",
    description: "List containers for an account",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ EVENT NOTIFICATIONS ============
  get_r2_event_notification_config: {
    name: "get_r2_event_notification_config",
    description: "Get R2 bucket event notification configuration",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      bucket_name: z.string().describe("The R2 bucket name"),
    }),
  },

  // ============ ZONE: API GATEWAY ============
  get_api_gateway_config: {
    name: "get_api_gateway_config",
    description: "Get API Gateway configuration for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  get_api_gateway_discovery: {
    name: "get_api_gateway_discovery",
    description: "Get API Gateway discovery status",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  list_api_gateway_operations: {
    name: "list_api_gateway_operations",
    description: "List API Gateway operations for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  get_api_gateway_operation: {
    name: "get_api_gateway_operation",
    description: "Get details of an API Gateway operation",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
      operation_id: z.string().describe("The operation ID"),
    }),
  },

  list_api_gateway_schemas: {
    name: "list_api_gateway_schemas",
    description: "List API Gateway schemas for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  list_api_gateway_user_schemas: {
    name: "list_api_gateway_user_schemas",
    description: "List API Gateway user-uploaded schemas",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  get_api_gateway_user_schema: {
    name: "get_api_gateway_user_schema",
    description: "Get details of an API Gateway user schema",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
      schema_id: z.string().describe("The schema ID"),
    }),
  },

  get_api_gateway_settings: {
    name: "get_api_gateway_settings",
    description: "Get API Gateway schema validation settings",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: SPECTRUM (Analytics) ============
  get_spectrum_analytics_summary: {
    name: "get_spectrum_analytics_summary",
    description: "Get Spectrum analytics summary",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: CONTENT UPLOAD SCAN ============
  get_content_upload_scan_settings: {
    name: "get_content_upload_scan_settings",
    description: "Get content upload scan (malware) settings for a zone",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ ZONE: HOLD ============
  get_zone_hold: {
    name: "get_zone_hold",
    description: "Get zone hold status",
    inputSchema: z.object({
      zone_id: z.string().describe("The zone ID"),
    }),
  },

  // ============ SHARES (R2) ============
  get_r2_share: {
    name: "get_r2_share",
    description: "Get details of an R2 share",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      share_id: z.string().describe("The share ID"),
    }),
  },

  list_r2_share_recipients: {
    name: "list_r2_share_recipients",
    description: "List recipients of an R2 share",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      share_id: z.string().describe("The share ID"),
    }),
  },

  list_r2_share_resources: {
    name: "list_r2_share_resources",
    description: "List resources in an R2 share",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      share_id: z.string().describe("The share ID"),
    }),
  },

  // ============ SLURPER (MIGRATION) ============
  list_slurper_jobs: {
    name: "list_slurper_jobs",
    description: "List migration (slurper) jobs",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_slurper_job: {
    name: "get_slurper_job",
    description: "Get details of a migration job",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      job_id: z.string().describe("The job ID"),
    }),
  },

  get_slurper_job_progress: {
    name: "get_slurper_job_progress",
    description: "Get progress of a migration job",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      job_id: z.string().describe("The job ID"),
    }),
  },

  // ============ BOTNET FEED ============
  get_botnet_feed_asn_config: {
    name: "get_botnet_feed_asn_config",
    description: "Get botnet feed ASN configuration",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_botnet_feed_asn_report: {
    name: "get_botnet_feed_asn_report",
    description: "Get botnet feed report for an ASN",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      asn_id: z.number().describe("The ASN ID"),
    }),
  },

  // ============ AUTORAG ============
  list_autorag_files: {
    name: "list_autorag_files",
    description: "List files in an AutoRAG instance",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      rag_id: z.string().describe("The AutoRAG instance ID"),
    }),
  },

  list_autorag_jobs: {
    name: "list_autorag_jobs",
    description: "List jobs for an AutoRAG instance",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      rag_id: z.string().describe("The AutoRAG instance ID"),
    }),
  },

  get_autorag_job: {
    name: "get_autorag_job",
    description: "Get details of an AutoRAG job",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      rag_id: z.string().describe("The AutoRAG instance ID"),
      job_id: z.string().describe("The job ID"),
    }),
  },

  // ============ DEX (Digital Experience) ============
  list_dex_colos: {
    name: "list_dex_colos",
    description: "List DEX colocations",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_dex_fleet_status_devices: {
    name: "list_dex_fleet_status_devices",
    description: "List DEX fleet status by device",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dex_fleet_status_live: {
    name: "get_dex_fleet_status_live",
    description: "Get live DEX fleet status",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dex_fleet_status_over_time: {
    name: "get_dex_fleet_status_over_time",
    description: "Get DEX fleet status over time",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_dex_tests_overview: {
    name: "list_dex_tests_overview",
    description: "List DEX tests overview",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dex_tests_unique_devices: {
    name: "get_dex_tests_unique_devices",
    description: "Get unique devices for DEX tests",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dex_http_test: {
    name: "get_dex_http_test",
    description: "Get DEX HTTP test details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      test_id: z.string().describe("The test ID"),
    }),
  },

  get_dex_traceroute_test: {
    name: "get_dex_traceroute_test",
    description: "Get DEX traceroute test details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      test_id: z.string().describe("The test ID"),
    }),
  },

  list_dex_rules: {
    name: "list_dex_rules",
    description: "List DEX rules",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dex_rule: {
    name: "get_dex_rule",
    description: "Get DEX rule details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      rule_id: z.string().describe("The rule ID"),
    }),
  },

  list_dex_commands: {
    name: "list_dex_commands",
    description: "List DEX commands",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_dex_commands_quota: {
    name: "get_dex_commands_quota",
    description: "Get DEX commands quota",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ BRAND PROTECTION ============
  list_brand_protection_alerts: {
    name: "list_brand_protection_alerts",
    description: "List brand protection alerts",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_brand_protection_brands: {
    name: "list_brand_protection_brands",
    description: "List registered brands for brand protection",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_brand_protection_logos: {
    name: "list_brand_protection_logos",
    description: "List brand protection logos",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_brand_protection_logo: {
    name: "get_brand_protection_logo",
    description: "Get brand protection logo details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      logo_id: z.string().describe("The logo ID"),
    }),
  },

  list_brand_protection_matches: {
    name: "list_brand_protection_matches",
    description: "List brand protection matches (potential infringements)",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_brand_protection_logo_matches: {
    name: "list_brand_protection_logo_matches",
    description: "List brand protection logo matches",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_brand_protection_queries: {
    name: "list_brand_protection_queries",
    description: "List brand protection queries",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_brand_protection_url_info: {
    name: "get_brand_protection_url_info",
    description: "Get brand protection URL info",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      url: z.string().optional().describe("URL to check"),
    }),
  },

  get_brand_protection_domain_info: {
    name: "get_brand_protection_domain_info",
    description: "Get brand protection domain info",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_brand_protection_tracked_domains: {
    name: "list_brand_protection_tracked_domains",
    description: "List brand protection tracked domains",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_brand_protection_recent_submissions: {
    name: "list_brand_protection_recent_submissions",
    description: "List recent brand protection submissions",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ EMAIL SECURITY ============
  list_email_security_investigate: {
    name: "list_email_security_investigate",
    description: "List email security investigation results",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_email_security_message: {
    name: "get_email_security_message",
    description: "Get email security message details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      postfix_id: z.string().describe("The message postfix ID"),
    }),
  },

  get_email_security_message_detections: {
    name: "get_email_security_message_detections",
    description: "Get email security message detections",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      postfix_id: z.string().describe("The message postfix ID"),
    }),
  },

  list_email_security_submissions: {
    name: "list_email_security_submissions",
    description: "List email security submissions",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_email_security_allow_policies: {
    name: "list_email_security_allow_policies",
    description: "List email security allow policies",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_email_security_allow_policy: {
    name: "get_email_security_allow_policy",
    description: "Get email security allow policy details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      policy_id: z.string().describe("The policy ID"),
    }),
  },

  list_email_security_block_senders: {
    name: "list_email_security_block_senders",
    description: "List email security blocked senders",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_email_security_block_sender: {
    name: "get_email_security_block_sender",
    description: "Get email security blocked sender details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      pattern_id: z.string().describe("The pattern ID"),
    }),
  },

  list_email_security_domains: {
    name: "list_email_security_domains",
    description: "List email security domains",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_email_security_domain: {
    name: "get_email_security_domain",
    description: "Get email security domain details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      domain_id: z.string().describe("The domain ID"),
    }),
  },

  list_email_security_impersonation_registry: {
    name: "list_email_security_impersonation_registry",
    description: "List email security impersonation registry",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_email_security_trusted_domains: {
    name: "list_email_security_trusted_domains",
    description: "List email security trusted domains",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_email_security_phishguard_reports: {
    name: "get_email_security_phishguard_reports",
    description: "Get email security Phishguard reports",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ REALTIME KIT ============
  list_realtime_apps: {
    name: "list_realtime_apps",
    description: "List Realtime Kit apps",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_realtime_analytics_daywise: {
    name: "get_realtime_analytics_daywise",
    description: "Get Realtime Kit daily analytics",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  list_realtime_livestreams: {
    name: "list_realtime_livestreams",
    description: "List Realtime Kit livestreams",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  get_realtime_livestream: {
    name: "get_realtime_livestream",
    description: "Get Realtime Kit livestream details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      livestream_id: z.string().describe("The livestream ID"),
    }),
  },

  list_realtime_meetings: {
    name: "list_realtime_meetings",
    description: "List Realtime Kit meetings",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  get_realtime_meeting: {
    name: "get_realtime_meeting",
    description: "Get Realtime Kit meeting details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      meeting_id: z.string().describe("The meeting ID"),
    }),
  },

  list_realtime_meeting_participants: {
    name: "list_realtime_meeting_participants",
    description: "List participants in a Realtime Kit meeting",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      meeting_id: z.string().describe("The meeting ID"),
    }),
  },

  list_realtime_presets: {
    name: "list_realtime_presets",
    description: "List Realtime Kit presets",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  get_realtime_preset: {
    name: "get_realtime_preset",
    description: "Get Realtime Kit preset details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      preset_id: z.string().describe("The preset ID"),
    }),
  },

  list_realtime_recordings: {
    name: "list_realtime_recordings",
    description: "List Realtime Kit recordings",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  get_realtime_recording: {
    name: "get_realtime_recording",
    description: "Get Realtime Kit recording details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      recording_id: z.string().describe("The recording ID"),
    }),
  },

  list_realtime_sessions: {
    name: "list_realtime_sessions",
    description: "List Realtime Kit sessions",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  get_realtime_session: {
    name: "get_realtime_session",
    description: "Get Realtime Kit session details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      session_id: z.string().describe("The session ID"),
    }),
  },

  get_realtime_session_summary: {
    name: "get_realtime_session_summary",
    description: "Get Realtime Kit session summary",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      session_id: z.string().describe("The session ID"),
    }),
  },

  get_realtime_session_transcript: {
    name: "get_realtime_session_transcript",
    description: "Get Realtime Kit session transcript",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      session_id: z.string().describe("The session ID"),
    }),
  },

  list_realtime_webhooks: {
    name: "list_realtime_webhooks",
    description: "List Realtime Kit webhooks",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
    }),
  },

  get_realtime_webhook: {
    name: "get_realtime_webhook",
    description: "Get Realtime Kit webhook details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      app_id: z.string().describe("The Realtime app ID"),
      webhook_id: z.string().describe("The webhook ID"),
    }),
  },

  // ============ ZERO TRUST SETTINGS ============
  get_zerotrust_connectivity_settings: {
    name: "get_zerotrust_connectivity_settings",
    description: "Get Zero Trust connectivity settings",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_zerotrust_hostname_routes: {
    name: "list_zerotrust_hostname_routes",
    description: "List Zero Trust hostname routes",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_zerotrust_hostname_route: {
    name: "get_zerotrust_hostname_route",
    description: "Get Zero Trust hostname route details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      hostname_route_id: z.string().describe("The hostname route ID"),
    }),
  },

  list_zerotrust_subnets: {
    name: "list_zerotrust_subnets",
    description: "List Zero Trust subnets",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  // ============ CLOUDFORCE ONE ============
  list_cloudforce_one_events: {
    name: "list_cloudforce_one_events",
    description: "List Cloudforce One threat events",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_cloudforce_one_event: {
    name: "get_cloudforce_one_event",
    description: "Get Cloudforce One threat event details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      event_id: z.string().describe("The event ID"),
    }),
  },

  get_cloudforce_one_events_aggregate: {
    name: "get_cloudforce_one_events_aggregate",
    description: "Get Cloudforce One events aggregate",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_categories: {
    name: "list_cloudforce_one_categories",
    description: "List Cloudforce One event categories",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_countries: {
    name: "list_cloudforce_one_countries",
    description: "List Cloudforce One event countries",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_datasets: {
    name: "list_cloudforce_one_datasets",
    description: "List Cloudforce One datasets",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_cloudforce_one_dataset: {
    name: "get_cloudforce_one_dataset",
    description: "Get Cloudforce One dataset details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      dataset_id: z.string().describe("The dataset ID"),
    }),
  },

  list_cloudforce_one_indicators: {
    name: "list_cloudforce_one_indicators",
    description: "List Cloudforce One threat indicators",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_indicator_types: {
    name: "list_cloudforce_one_indicator_types",
    description: "List Cloudforce One indicator types",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_tags: {
    name: "list_cloudforce_one_tags",
    description: "List Cloudforce One tags",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_target_industries: {
    name: "list_cloudforce_one_target_industries",
    description: "List Cloudforce One target industries",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_queries: {
    name: "list_cloudforce_one_queries",
    description: "List Cloudforce One queries",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_cloudforce_one_query: {
    name: "get_cloudforce_one_query",
    description: "Get Cloudforce One query details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      query_id: z.string().describe("The query ID"),
    }),
  },

  get_cloudforce_one_request: {
    name: "get_cloudforce_one_request",
    description: "Get Cloudforce One request details",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
      request_id: z.string().describe("The request ID"),
    }),
  },

  get_cloudforce_one_requests_quota: {
    name: "get_cloudforce_one_requests_quota",
    description: "Get Cloudforce One requests quota",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  list_cloudforce_one_request_types: {
    name: "list_cloudforce_one_request_types",
    description: "List Cloudforce One request types",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },

  get_cloudforce_one_scans_config: {
    name: "get_cloudforce_one_scans_config",
    description: "Get Cloudforce One scans configuration",
    inputSchema: z.object({
      account_id: z.string().describe("The account ID"),
    }),
  },
};

export type ToolName = keyof typeof toolDefinitions;
