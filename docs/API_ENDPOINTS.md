# Cloudflare API Endpoints Reference

Base URL: `https://api.cloudflare.com/client/v4`

OpenAPI Schemas: https://github.com/cloudflare/api-schemas

**OpenAPI Spec:** See `context/openapi.json` (1639 total endpoints)

## Authentication

All requests require either:
- **API Token** (recommended): `Authorization: Bearer <token>`
- **API Key** (legacy): `X-Auth-Email: <email>` + `X-Auth-Key: <key>`

---

## MCP Server Implementation Status

### ✅ Implemented (354 tools)
- Accounts, Audit Logs, Zones, Zone Settings
- SSL/TLS (certificates, verification, universal SSL, keyless SSL)
- Rate Limiting (modern + legacy)
- Rulesets (WAF custom/managed, transform rules, cache rules, DDoS)
- DNS Records, Firewall Rules, Page Rules, Filters
- Workers (scripts, routes, services, secrets, deployments, tails)
- Load Balancing (load balancers, pools, monitors)
- Custom Hostnames, Access (apps, policies, groups, service tokens)
- Bot Management, Argo, Waiting Rooms, Cache Settings
- Analytics (dashboard, colo, GraphQL)
- D1, R2, KV, Durable Objects, Queues
- Tunnels (list, get, connections, configurations), Logpush, Email Routing
- Pages, Stream, Images, Registrar
- Healthchecks, IP Access Rules, Zone Lockdown, User Agent Rules
- Origin CA, Client Certificates, Authenticated Origin Pulls
- Snippets, Web3 Hostnames, Zaraz
- Workers AI, Vectorize, AI Gateway
- User, Billing, Zone Subscription, Devices, DNSSEC
- **Page Shield** (settings, scripts, connections, policies)
- **Security Center** (insights)
- **Alerting/Notifications** (policies, history, available alerts, webhooks)
- **Turnstile** (widgets)
- **Gateway (Zero Trust)** (rules, configuration, locations, proxy endpoints)
- **Hyperdrive** (configs)
- **URL Normalization, Managed Headers**
- **Magic Transit** (IPsec tunnels, GRE tunnels, routes, connectors, sites)
- **DNS Firewall** (clusters, analytics)
- **Secondary DNS** (primary, peers, TSIGs, incoming/outgoing, ACLs)
- **Speed API** (tests, schedules, regions, trends)
- **Calls (WebRTC)** (apps, TURN keys)
- **DLP** (profiles, datasets, patterns, payload log settings)
- **Cloudflare IPs** (IP ranges for allowlisting)
- **Memberships** (user account memberships)
- **Access Extended** (bookmarks, certificates, custom pages, identity providers, keys, logs, organization, tags, users)
- **AI Gateway Extended** (datasets, evaluations, routes)
- **IP Addressing (BYOIP)** (address maps, prefixes, BGP status, delegations, services)
- **URL Scanner** (scan results, HAR files)
- **AI Search** (instances, items, jobs)
- **Workers Builds** (builds list/get)
- **Workers Workflows** (workflows, instances)
- **CNI (Interconnect)** (interconnects, slots, settings)
- **R2 Pipelines** (pipelines list/get)
- **IAM/Permissions** (permission groups, resource groups)
- **Zero Trust Risk Scoring** (behaviors, integrations)
- **R2 Catalog** (catalogs list/get)
- **Team Network Routes** (routes, virtual networks)
- **Secrets Store** (stores, secrets list)
- **Packet Captures** (pcaps, ownership)
- **Magic Network Monitoring** (config, rules)
- **WARP Connector** (connectors list/get)
- **mTLS Certificates (Account)** (certificates list/get)
- **Account DNS Settings** (settings, views)
- **Zone: API Schema Validation** (settings, schemas)
- **Zone: Token Validation** (settings)
- **Zone: Smart Shield** (settings)
- **Zone: Logs** (retention settings)
- **Zone: Leaked Credential Checks** (settings, detections)
- **Zone: Advanced Certificate Manager** (Total TLS settings)
- **Zone: DNS Analytics** (reports)
- **Zone: Fraud Detection** (settings)
- **Zone: Cloud Connector** (rules)
- **Zone: DCV Delegation** (UUID)
- **Intel** (ASN, domain, IP, whois, indicator feeds, sinkholes, IP lists)
- **Rules/Lists** (account-level IP/hostname lists)
- **API Tokens** (tokens list/get, verify, permission groups)
- **RUM** (Real User Monitoring sites)
- **Abuse Reports** (reports list/get)
- **Infrastructure Targets** (targets list/get)
- **Connectivity Services** (directory services)
- **Diagnostics** (endpoint healthchecks)
- **Containers** (container registry)
- **Event Notifications** (R2 bucket notifications)
- **Zone: API Gateway** (config, discovery, operations, schemas)
- **Zone: Spectrum Analytics** (analytics summary)
- **Zone: Content Upload Scan** (malware scanning settings)
- **Zone: Hold** (zone hold status)
- **R2 Shares** (shares, recipients, resources)
- **Slurper** (migration jobs, progress)
- **Botnet Feed** (ASN config, reports)
- **AutoRAG** (files, jobs)
- **DEX** (colos, fleet status, tests, HTTP tests, traceroute tests, rules, commands)
- **Brand Protection** (alerts, brands, logos, matches, queries, tracked domains)
- **Email Security** (investigate, submissions, allow policies, block senders, domains, impersonation registry, trusted domains, Phishguard)
- **Realtime Kit** (apps, analytics, livestreams, meetings, participants, presets, recordings, sessions, webhooks)
- **Zero Trust Settings** (connectivity settings, hostname routes, subnets)
- **Cloudforce One** (events, categories, countries, datasets, indicators, tags, target industries, queries, requests, scans)

### ❌ Not Implemented (Remaining Categories)
The following are available in the OpenAPI spec but not yet in the MCP server:

| Category | Key Endpoints | Notes |
|----------|---------------|-------|
| **Purge Cache** | `/zones/{zone_id}/purge_cache` | POST action only, not a GET |

---

## Accounts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts` | List all accounts |
| GET | `/accounts/{account_id}` | Get account details |
| GET | `/accounts/{account_id}/members` | List account members |
| GET | `/accounts/{account_id}/roles` | List account roles |

---

## Audit Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/audit_logs` | Get audit logs for an account |

**Query Parameters:**
- `since` - Start date (ISO 8601)
- `before` - End date (ISO 8601)
- `actor.email` - Filter by actor email
- `actor.ip` - Filter by actor IP
- `action.type` - Filter by action type
- `zone.name` - Filter by zone name
- `per_page` - Results per page (max 1000)
- `page` - Page number

---

## Zones

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones` | List all zones |
| GET | `/zones/{zone_id}` | Get zone details |
| GET | `/zones/{zone_id}/settings` | Get all zone settings |
| GET | `/zones/{zone_id}/settings/{setting_name}` | Get specific zone setting |

**Common Settings:**
- `ssl` - SSL/TLS encryption mode
- `always_use_https` - Always Use HTTPS
- `min_tls_version` - Minimum TLS Version
- `tls_1_3` - TLS 1.3 support
- `automatic_https_rewrites` - Automatic HTTPS Rewrites
- `security_level` - Security Level
- `waf` - Web Application Firewall (legacy)

---

## SSL/TLS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/ssl/certificate_packs` | List certificate packs |
| GET | `/zones/{zone_id}/ssl/certificate_packs/{certificate_pack_id}` | Get certificate pack |
| GET | `/zones/{zone_id}/ssl/verification` | Get SSL verification status |
| GET | `/zones/{zone_id}/custom_certificates` | List custom certificates |
| GET | `/zones/{zone_id}/custom_certificates/{certificate_id}` | Get custom certificate |
| GET | `/zones/{zone_id}/ssl/universal/settings` | Get Universal SSL settings |
| GET | `/zones/{zone_id}/settings/ssl` | Get SSL mode (off/flexible/full/strict) |
| GET | `/zones/{zone_id}/settings/min_tls_version` | Get minimum TLS version |
| GET | `/zones/{zone_id}/settings/tls_1_3` | Get TLS 1.3 status |

---

## Rate Limiting

### Modern WAF Rate Limiting (Rulesets API)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/rulesets` | List all rulesets |
| GET | `/zones/{zone_id}/rulesets/{ruleset_id}` | Get ruleset details |
| GET | `/zones/{zone_id}/rulesets/phases/http_ratelimit/entrypoint` | Get rate limiting ruleset |

### Account-Level Rate Limiting

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/rulesets` | List account rulesets |
| GET | `/accounts/{account_id}/rulesets/{ruleset_id}` | Get account ruleset |

### Legacy Rate Limiting (Deprecated)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/rate_limits` | List rate limiting rules |
| GET | `/zones/{zone_id}/rate_limits/{rate_limit_id}` | Get rate limit rule |

---

## Firewall / WAF

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/firewall/rules` | List firewall rules |
| GET | `/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint` | Get custom WAF rules |
| GET | `/zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint` | Get managed WAF rules |

---

## DNS Records

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/dns_records` | List DNS records |
| GET | `/zones/{zone_id}/dns_records/{dns_record_id}` | Get DNS record |

---

## Page Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/pagerules` | List page rules |
| GET | `/zones/{zone_id}/pagerules/{pagerule_id}` | Get page rule |

---

## Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/analytics/dashboard` | Get zone analytics |
| GET | `/zones/{zone_id}/analytics/colos` | Get analytics by colo |
| POST | `/graphql` | GraphQL Analytics API |

---

## Workers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/workers/scripts` | List Worker scripts |
| GET | `/accounts/{account_id}/workers/scripts/{script_name}` | Get Worker script |
| GET | `/accounts/{account_id}/workers/services` | List Worker services |
| GET | `/zones/{zone_id}/workers/routes` | List Worker routes |

---

## Load Balancing

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/load_balancers` | List load balancers |
| GET | `/accounts/{account_id}/load_balancers/pools` | List origin pools |
| GET | `/accounts/{account_id}/load_balancers/monitors` | List health monitors |

---

## Access (Zero Trust)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/access/apps` | List Access applications |
| GET | `/accounts/{account_id}/access/policies` | List Access policies |
| GET | `/accounts/{account_id}/access/groups` | List Access groups |
| GET | `/accounts/{account_id}/access/service_tokens` | List service tokens |

---

## Custom Hostnames (SSL for SaaS)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/custom_hostnames` | List custom hostnames |
| GET | `/zones/{zone_id}/custom_hostnames/{custom_hostname_id}` | Get custom hostname |

---

## Origin Rules & Transform Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint` | Get origin rules |
| GET | `/zones/{zone_id}/rulesets/phases/http_request_transform/entrypoint` | Get URL rewrite rules |
| GET | `/zones/{zone_id}/rulesets/phases/http_request_late_transform/entrypoint` | Get HTTP request header modification rules |
| GET | `/zones/{zone_id}/rulesets/phases/http_response_headers_transform/entrypoint` | Get HTTP response header modification rules |

---

## Cache

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/settings/cache_level` | Get cache level |
| GET | `/zones/{zone_id}/settings/browser_cache_ttl` | Get browser cache TTL |
| GET | `/zones/{zone_id}/rulesets/phases/http_request_cache_settings/entrypoint` | Get cache rules |

---

## Bot Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/bot_management` | Get bot management settings |

---

## DDoS Protection

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/rulesets/phases/ddos_l7/entrypoint` | Get L7 DDoS rules |
| GET | `/accounts/{account_id}/rulesets/phases/ddos_l4/entrypoint` | Get L4 DDoS rules |

---

## Waiting Room

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/waiting_rooms` | List waiting rooms |
| GET | `/zones/{zone_id}/waiting_rooms/{waiting_room_id}` | Get waiting room |

---

## Spectrum

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/spectrum/apps` | List Spectrum applications |

---

## Argo

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/argo/smart_routing` | Get Argo Smart Routing status |
| GET | `/zones/{zone_id}/argo/tiered_caching` | Get Tiered Caching status |

---

## API Shield

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/api_gateway/operations` | List API operations |
| GET | `/zones/{zone_id}/api_gateway/schemas` | List API schemas |
| GET | `/zones/{zone_id}/api_gateway/configuration` | Get API Shield configuration |

---

## D1 Databases

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/d1/database` | List D1 databases |
| GET | `/accounts/{account_id}/d1/database/{database_id}` | Get D1 database |

---

## R2 Storage

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/r2/buckets` | List R2 buckets |

---

## KV Namespaces

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/storage/kv/namespaces` | List KV namespaces |
| GET | `/accounts/{account_id}/storage/kv/namespaces/{namespace_id}` | Get KV namespace |
| GET | `/accounts/{account_id}/storage/kv/namespaces/{namespace_id}/keys` | List keys in namespace |

---

## Durable Objects

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/workers/durable_objects/namespaces` | List DO namespaces |

---

## Queues

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/queues` | List queues |
| GET | `/accounts/{account_id}/queues/{queue_id}` | Get queue |

---

## Tunnels

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/cfd_tunnel` | List tunnels |
| GET | `/accounts/{account_id}/cfd_tunnel/{tunnel_id}` | Get tunnel |
| GET | `/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections` | List tunnel connections |

---

## Logpush

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/logpush/jobs` | List zone logpush jobs |
| GET | `/accounts/{account_id}/logpush/jobs` | List account logpush jobs |

---

## Email Routing

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/email/routing` | Get email routing settings |
| GET | `/zones/{zone_id}/email/routing/rules` | List email routing rules |
| GET | `/accounts/{account_id}/email/routing/addresses` | List destination addresses |

---

## Pages

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/pages/projects` | List Pages projects |
| GET | `/accounts/{account_id}/pages/projects/{project_name}` | Get Pages project |
| GET | `/accounts/{account_id}/pages/projects/{project_name}/deployments` | List deployments |

---

## Stream

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/stream` | List videos |
| GET | `/accounts/{account_id}/stream/{video_id}` | Get video |

---

## Images

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/images/v1` | List images |
| GET | `/accounts/{account_id}/images/v1/stats` | Get images stats |

---

## Registrar

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/registrar/domains` | List domains |
| GET | `/accounts/{account_id}/registrar/domains/{domain_name}` | Get domain |

---

## Healthchecks

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/healthchecks` | List healthchecks |
| GET | `/zones/{zone_id}/healthchecks/{healthcheck_id}` | Get healthcheck |

---

## IP Access Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/firewall/access_rules/rules` | List IP access rules |

---

## Zone Lockdown

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/firewall/lockdowns` | List zone lockdown rules |

---

## User Agent Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/firewall/ua_rules` | List user agent rules |

---

## Origin CA Certificates

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/certificates?zone_id={zone_id}` | List Origin CA certificates |

---

## Client Certificates (mTLS)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/client_certificates` | List client certificates |

---

## Authenticated Origin Pulls

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/origin_tls_client_auth/settings` | Get AOP settings |

---

## Filters

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/filters` | List filters |

---

## Snippets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/snippets` | List snippets |

---

## Web3 Hostnames

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/web3/hostnames` | List Web3 hostnames |

---

## Zaraz

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/zaraz/config` | Get Zaraz configuration |

---

## Workers AI

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/ai/models/search` | List available AI models |

---

## Vectorize

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/vectorize/indexes` | List vector indexes |
| GET | `/accounts/{account_id}/vectorize/indexes/{index_name}` | Get vector index details |

---

## AI Gateway

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/ai-gateway/gateways` | List AI gateways |
| GET | `/accounts/{account_id}/ai-gateway/gateways/{gateway_id}/logs` | Get gateway logs |

---

## Workers Secrets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/workers/scripts/{script_name}/secrets` | List Worker secrets (names only) |

---

## Workers Deployments

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/workers/scripts/{script_name}/deployments` | List Worker deployments |

---

## Workers Tail Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/workers/scripts/{script_name}/tails` | List active tail sessions |

---

## User

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/user` | Get current authenticated user details |
| GET | `/user/tokens/verify` | Verify API token |

---

## Billing

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/billing/profile` | Get billing profile |

---

## Zone Subscription

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/subscription` | Get zone subscription (Free/Pro/Business/Enterprise) |

---

## Devices (Zero Trust)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/devices` | List enrolled devices |
| GET | `/accounts/{account_id}/devices/posture` | List device posture rules |
| GET | `/accounts/{account_id}/devices/policies` | List device policies |

---

## DNSSEC

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/dnssec` | Get DNSSEC status |

---

## Page Shield

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/page_shield` | Get Page Shield settings |
| GET | `/zones/{zone_id}/page_shield/scripts` | List detected scripts |
| GET | `/zones/{zone_id}/page_shield/connections` | List detected connections |
| GET | `/zones/{zone_id}/page_shield/policies` | List Page Shield policies |

---

## Security Center

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/security-center/insights` | List security insights |

---

## Alerting/Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/alerting/v3/policies` | List notification policies |
| GET | `/accounts/{account_id}/alerting/v3/history` | List notification history |
| GET | `/accounts/{account_id}/alerting/v3/available_alerts` | List available alert types |
| GET | `/accounts/{account_id}/alerting/v3/destinations/webhooks` | List webhook destinations |

---

## Turnstile (Challenges)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/challenges/widgets` | List Turnstile widgets |
| GET | `/accounts/{account_id}/challenges/widgets/{sitekey}` | Get widget details |

---

## Gateway (Zero Trust)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/gateway/rules` | List Gateway rules |
| GET | `/accounts/{account_id}/gateway/configuration` | Get Gateway configuration |
| GET | `/accounts/{account_id}/gateway/locations` | List Gateway locations |
| GET | `/accounts/{account_id}/gateway/proxy_endpoints` | List proxy endpoints |

---

## Hyperdrive

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/hyperdrive/configs` | List Hyperdrive configs |
| GET | `/accounts/{account_id}/hyperdrive/configs/{id}` | Get Hyperdrive config |

---

## URL Normalization

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/url_normalization` | Get URL normalization settings |

---

## Managed Headers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/managed_headers` | Get managed headers config |

---

## Keyless SSL

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/keyless_certificates` | List Keyless SSL certificates |

---

## Magic Transit

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/magic/ipsec_tunnels` | List IPsec tunnels |
| GET | `/accounts/{account_id}/magic/ipsec_tunnels/{tunnel_id}` | Get IPsec tunnel |
| GET | `/accounts/{account_id}/magic/gre_tunnels` | List GRE tunnels |
| GET | `/accounts/{account_id}/magic/gre_tunnels/{tunnel_id}` | Get GRE tunnel |
| GET | `/accounts/{account_id}/magic/routes` | List static routes |
| GET | `/accounts/{account_id}/magic/routes/{route_id}` | Get static route |
| GET | `/accounts/{account_id}/magic/connectors` | List connectors |
| GET | `/accounts/{account_id}/magic/connectors/{connector_id}` | Get connector |
| GET | `/accounts/{account_id}/magic/sites` | List Magic WAN sites |
| GET | `/accounts/{account_id}/magic/sites/{site_id}` | Get Magic WAN site |

---

## DNS Firewall

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/dns_firewall` | List DNS Firewall clusters |
| GET | `/accounts/{account_id}/dns_firewall/{cluster_id}` | Get DNS Firewall cluster |
| GET | `/accounts/{account_id}/dns_firewall/{cluster_id}/dns_analytics/report` | Get DNS Firewall analytics |

---

## Secondary DNS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/secondary_dns/primaries` | Get primary nameserver config |
| GET | `/accounts/{account_id}/secondary_dns/peers` | List secondary DNS peers |
| GET | `/accounts/{account_id}/secondary_dns/peers/{peer_id}` | Get secondary DNS peer |
| GET | `/accounts/{account_id}/secondary_dns/tsigs` | List TSIG keys |
| GET | `/accounts/{account_id}/secondary_dns/tsigs/{tsig_id}` | Get TSIG key |
| GET | `/zones/{zone_id}/secondary_dns/incoming` | Get incoming zone transfer config |
| GET | `/zones/{zone_id}/secondary_dns/outgoing` | Get outgoing zone transfer config |
| GET | `/accounts/{account_id}/secondary_dns/acls` | List secondary DNS ACLs |
| GET | `/accounts/{account_id}/secondary_dns/acls/{acl_id}` | Get secondary DNS ACL |

---

## Speed API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zones/{zone_id}/speed_api/pages/{url}/tests` | List speed tests for URL |
| GET | `/zones/{zone_id}/speed_api/pages/{url}/tests/{test_id}` | Get speed test details |
| GET | `/zones/{zone_id}/speed_api/schedule/{url}` | Get scheduled test config |
| GET | `/zones/{zone_id}/speed_api/availabilities` | List available test regions |
| GET | `/zones/{zone_id}/speed_api/pages/{url}/trend` | Get page speed trends |

---

## Calls (WebRTC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/calls/apps` | List Calls applications |
| GET | `/accounts/{account_id}/calls/apps/{app_id}` | Get Calls application |
| GET | `/accounts/{account_id}/calls/turn_keys` | List TURN keys |
| GET | `/accounts/{account_id}/calls/turn_keys/{key_id}` | Get TURN key |

---

## DLP (Data Loss Prevention)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{account_id}/dlp/profiles` | List DLP profiles |
| GET | `/accounts/{account_id}/dlp/profiles/{profile_id}` | Get DLP profile |
| GET | `/accounts/{account_id}/dlp/datasets` | List DLP datasets |
| GET | `/accounts/{account_id}/dlp/datasets/{dataset_id}` | Get DLP dataset |
| GET | `/accounts/{account_id}/dlp/patterns` | List predefined DLP patterns |
| GET | `/accounts/{account_id}/dlp/payload_log` | Get payload logging settings |

---

## Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Internal Server Error |

---

## Pagination

Most list endpoints support:
- `page` - Page number (default: 1)
- `per_page` - Results per page (default: 20, max: 1000 for most endpoints)

Response includes:
```json
{
  "result": [...],
  "result_info": {
    "page": 1,
    "per_page": 20,
    "total_pages": 5,
    "count": 20,
    "total_count": 100
  }
}
```
