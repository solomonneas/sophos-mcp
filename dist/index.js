#!/usr/bin/env node

// src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// src/config.ts
var SOPHOS_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token";
var SOPHOS_GLOBAL_URL = "https://api.central.sophos.com";
function getConfig() {
  const clientId = process.env.SOPHOS_CLIENT_ID;
  if (!clientId) {
    throw new Error(
      "SOPHOS_CLIENT_ID environment variable is required. Create API credentials in Sophos Central > Global Settings > API Credentials Management."
    );
  }
  const clientSecret = process.env.SOPHOS_CLIENT_SECRET;
  if (!clientSecret) {
    throw new Error(
      "SOPHOS_CLIENT_SECRET environment variable is required. Create API credentials in Sophos Central > Global Settings > API Credentials Management."
    );
  }
  const tenantId = process.env.SOPHOS_TENANT_ID;
  const apiUrl = process.env.SOPHOS_API_URL?.replace(/\/+$/, "");
  const authUrl = (process.env.SOPHOS_AUTH_URL || SOPHOS_AUTH_URL).replace(/\/+$/, "");
  const globalUrl = SOPHOS_GLOBAL_URL;
  const timeout = parseInt(process.env.SOPHOS_TIMEOUT ?? "30", 10) * 1e3;
  return {
    clientId,
    clientSecret,
    tenantId,
    apiUrl,
    authUrl,
    globalUrl,
    timeout
  };
}

// src/client.ts
var SophosClientError = class extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.name = "SophosClientError";
  }
};
var SophosAuthError = class extends SophosClientError {
  constructor(message, statusCode) {
    super(message, statusCode);
    this.name = "SophosAuthError";
  }
};
var SophosRateLimitError = class extends SophosClientError {
  retryAfter;
  constructor(message, retryAfter) {
    super(message, 429);
    this.name = "SophosRateLimitError";
    this.retryAfter = retryAfter;
  }
};
var SophosClient = class {
  config;
  accessToken;
  tokenExpiresAt;
  dataRegionUrl;
  tenantId;
  constructor(config) {
    this.config = config;
    this.tenantId = config.tenantId;
    this.dataRegionUrl = config.apiUrl;
  }
  // --------------------------------------------------------------------------
  // OAuth2 Authentication
  // --------------------------------------------------------------------------
  /**
   * Obtain or refresh the OAuth2 access token using client credentials.
   */
  async authenticate() {
    if (this.accessToken && this.tokenExpiresAt && Date.now() < this.tokenExpiresAt) {
      return this.accessToken;
    }
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: "token"
    });
    const { signal, clear } = this.createAbortSignal();
    let response;
    try {
      response = await fetch(this.config.authUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: body.toString(),
        signal
      });
    } catch (error) {
      clear();
      if (error instanceof Error && error.name === "AbortError") {
        throw new SophosClientError(
          `OAuth2 token request timed out after ${this.config.timeout}ms`
        );
      }
      throw error;
    }
    clear();
    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new SophosAuthError(
        `OAuth2 authentication failed (${response.status}): ${errorText}`,
        response.status
      );
    }
    const tokenData = await response.json();
    if (tokenData.errorCode) {
      throw new SophosAuthError(
        `OAuth2 error: ${tokenData.errorCode} \u2014 ${tokenData.message}`
      );
    }
    this.accessToken = tokenData.access_token;
    this.tokenExpiresAt = Date.now() + (tokenData.expires_in - 60) * 1e3;
    return this.accessToken;
  }
  /**
   * Discover the data region URL and tenant ID using the whoami endpoint.
   */
  async discoverTenant() {
    if (this.dataRegionUrl && this.tenantId) {
      return;
    }
    const token = await this.authenticate();
    const { signal, clear } = this.createAbortSignal();
    let response;
    try {
      response = await fetch(`${this.config.globalUrl}/whoami/v1`, {
        headers: {
          Authorization: `Bearer ${token}`
        },
        signal
      });
    } catch (error) {
      clear();
      throw error;
    }
    clear();
    if (!response.ok) {
      throw new SophosClientError(
        `Tenant discovery failed (${response.status})`,
        response.status
      );
    }
    const whoami = await response.json();
    this.dataRegionUrl = this.dataRegionUrl || whoami.apiHosts.dataRegion;
    this.tenantId = this.tenantId || whoami.id;
  }
  // --------------------------------------------------------------------------
  // Core HTTP
  // --------------------------------------------------------------------------
  createAbortSignal() {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
    return {
      signal: controller.signal,
      clear: () => clearTimeout(timeoutId)
    };
  }
  /**
   * Send an authenticated request to the Sophos Central API.
   */
  async request(method, endpoint, params, body, useGlobalUrl = false) {
    await this.discoverTenant();
    const token = await this.authenticate();
    const baseUrl = useGlobalUrl ? this.config.globalUrl : this.dataRegionUrl;
    const url = new URL(`${baseUrl}${endpoint}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== void 0 && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }
    const headers = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    };
    if (!useGlobalUrl && this.tenantId) {
      headers["X-Tenant-ID"] = this.tenantId;
    }
    const { signal, clear } = this.createAbortSignal();
    let response;
    try {
      response = await fetch(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : void 0,
        signal
      });
    } catch (error) {
      clear();
      if (error instanceof Error && error.name === "AbortError") {
        throw new SophosClientError(
          `Sophos Central API timeout after ${this.config.timeout}ms`
        );
      }
      throw error;
    }
    clear();
    if (!response.ok) {
      await this.handleErrorResponse(response);
    }
    if (response.status === 204) {
      return {};
    }
    return await response.json();
  }
  async handleErrorResponse(response) {
    let errorMsg = `${response.status} ${response.statusText}`;
    try {
      const errorBody = await response.json();
      if (errorBody.message) {
        errorMsg = `${errorMsg}: ${errorBody.message}`;
      } else if (errorBody.error) {
        errorMsg = `${errorMsg}: ${errorBody.error}`;
      }
    } catch {
    }
    if (response.status === 401 || response.status === 403) {
      this.accessToken = void 0;
      this.tokenExpiresAt = void 0;
      throw new SophosAuthError(
        `Authentication failed: ${errorMsg}`,
        response.status
      );
    }
    if (response.status === 429) {
      const retryAfter = response.headers.get("Retry-After");
      throw new SophosRateLimitError(
        `Rate limited: ${errorMsg}`,
        retryAfter ? parseInt(retryAfter, 10) : void 0
      );
    }
    throw new SophosClientError(
      `Request failed: ${errorMsg}`,
      response.status
    );
  }
  async get(endpoint, params, useGlobalUrl = false) {
    return this.request("GET", endpoint, params, void 0, useGlobalUrl);
  }
  async post(endpoint, body, params, useGlobalUrl = false) {
    return this.request("POST", endpoint, params, body, useGlobalUrl);
  }
  async patch(endpoint, body, params) {
    return this.request("PATCH", endpoint, params, body);
  }
  async delete(endpoint, params) {
    return this.request("DELETE", endpoint, params);
  }
  // --------------------------------------------------------------------------
  // Endpoint Methods
  // --------------------------------------------------------------------------
  /** List endpoints with optional filters */
  async getEndpoints(params = {}) {
    return this.get("/endpoint/v1/endpoints", params);
  }
  /** Get a single endpoint by ID */
  async getEndpoint(endpointId) {
    return this.get(`/endpoint/v1/endpoints/${endpointId}`);
  }
  /** Isolate an endpoint */
  async isolateEndpoint(endpointId, comment) {
    return this.post(`/endpoint/v1/endpoints/${endpointId}/isolation`, {
      enabled: true,
      comment
    });
  }
  /** Remove isolation from an endpoint */
  async unisolateEndpoint(endpointId, comment) {
    return this.post(`/endpoint/v1/endpoints/${endpointId}/isolation`, {
      enabled: false,
      comment
    });
  }
  /** Trigger an on-demand scan on an endpoint */
  async scanEndpoint(endpointId) {
    return this.post(`/endpoint/v1/endpoints/${endpointId}/scans`, {
      type: "full"
    });
  }
  /** Get installed software on an endpoint */
  async getEndpointSoftware(endpointId, params = {}) {
    return this.get(`/endpoint/v1/endpoints/${endpointId}/software`, params);
  }
  // --------------------------------------------------------------------------
  // Alert Methods
  // --------------------------------------------------------------------------
  /** List alerts with optional filters */
  async getAlerts(params = {}) {
    return this.get("/common/v1/alerts", params);
  }
  /** Get a single alert by ID */
  async getAlert(alertId) {
    return this.get(`/common/v1/alerts/${alertId}`);
  }
  /** Perform an action on an alert (acknowledge, cleanPua, etc.) */
  async performAlertAction(alertId, action, message) {
    return this.post(`/common/v1/alerts/${alertId}/actions`, {
      action,
      message
    });
  }
  // --------------------------------------------------------------------------
  // Detection Methods
  // --------------------------------------------------------------------------
  /** List EDR/XDR detections */
  async getDetections(params = {}) {
    return this.get("/xdr/v1/detections", params);
  }
  /** Get a single detection by ID */
  async getDetection(detectionId) {
    return this.get(`/xdr/v1/detections/${detectionId}`);
  }
  /** List threat cases */
  async getThreatCases(params = {}) {
    return this.get("/xdr/v1/threat-cases", params);
  }
  /** Get detections for a specific threat case */
  async getCaseDetections(caseId, params = {}) {
    return this.get(`/xdr/v1/threat-cases/${caseId}/detections`, params);
  }
  /** Update threat case status */
  async updateCaseStatus(caseId, status, assigneeId) {
    const body = { status };
    if (assigneeId) body.assignee = { id: assigneeId };
    return this.patch(`/xdr/v1/threat-cases/${caseId}`, body);
  }
  // --------------------------------------------------------------------------
  // Event Methods
  // --------------------------------------------------------------------------
  /** Search security events */
  async getEvents(params = {}) {
    return this.get("/siem/v1/events", params);
  }
  /** Get a single event by ID */
  async getEvent(eventId) {
    return this.get(`/siem/v1/events/${eventId}`);
  }
  /** Get audit logs */
  async getAuditLogs(params = {}) {
    return this.get("/siem/v1/audit/events", params);
  }
  // --------------------------------------------------------------------------
  // Policy Methods
  // --------------------------------------------------------------------------
  /** List policies */
  async getPolicies(params = {}) {
    return this.get("/endpoint/v1/policies", params);
  }
  /** Get a single policy by ID */
  async getPolicy(policyId) {
    return this.get(`/endpoint/v1/policies/${policyId}`);
  }
  /** List scanning exclusions */
  async getExclusions(params = {}) {
    return this.get("/endpoint/v1/settings/exclusions/scanning", params);
  }
  // --------------------------------------------------------------------------
  // Tenant Methods
  // --------------------------------------------------------------------------
  /** List managed tenants (partner/organization view) */
  async getTenants(params = {}) {
    return this.get("/partner/v1/tenants", params, true);
  }
  /** Get a single tenant by ID */
  async getTenant(tenantId) {
    return this.get(`/partner/v1/tenants/${tenantId}`, void 0, true);
  }
  // --------------------------------------------------------------------------
  // Live Discover Methods
  // --------------------------------------------------------------------------
  /** Execute a Live Discover query */
  async runLiveDiscoverQuery(sql, endpointIds, variables) {
    return this.post("/live-discover/v1/queries/runs", {
      sql,
      matchEndpoints: endpointIds.map((id) => ({ id })),
      variables: variables ? Object.entries(variables).map(([name, value]) => ({ name, value })) : void 0
    });
  }
  /** List saved Live Discover queries */
  async getSavedQueries(params = {}) {
    return this.get("/live-discover/v1/queries", params);
  }
  /** Get results for a Live Discover query run */
  async getQueryResults(queryRunId, params = {}) {
    return this.get(`/live-discover/v1/queries/runs/${queryRunId}/results`, params);
  }
};

// src/tools/endpoints.ts
import { z } from "zod";
function registerEndpointTools(server, client) {
  server.tool(
    "list_endpoints",
    "List Sophos Central managed endpoints with optional filters for hostname, health status, OS platform, type, group, tamper protection, and isolation state",
    {
      search: z.string().optional().describe("Search by hostname, IP address, or associated person name"),
      healthStatus: z.enum(["good", "suspicious", "bad", "unknown"]).optional().describe("Filter by overall health status"),
      type: z.enum(["computer", "server", "securityVm"]).optional().describe("Filter by endpoint type"),
      os_platform: z.enum(["windows", "linux", "macOS"]).optional().describe("Filter by operating system platform"),
      tamperProtectionEnabled: z.boolean().optional().describe("Filter by tamper protection status"),
      isolationStatus: z.enum(["isolated", "notIsolated"]).optional().describe("Filter by network isolation status"),
      groupId: z.string().optional().describe("Filter by endpoint group ID"),
      lastSeenBefore: z.string().optional().describe("Filter endpoints last seen before this ISO 8601 timestamp"),
      lastSeenAfter: z.string().optional().describe("Filter endpoints last seen after this ISO 8601 timestamp"),
      pageSize: z.number().int().min(1).max(500).default(50).describe("Number of results to return (1-500)"),
      page: z.number().int().min(1).default(1).describe("Page number")
    },
    async ({
      search,
      healthStatus,
      type,
      os_platform,
      tamperProtectionEnabled,
      isolationStatus,
      groupId,
      lastSeenBefore,
      lastSeenAfter,
      pageSize,
      page
    }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (search) params.search = search;
        if (healthStatus) params.healthStatus = healthStatus;
        if (type) params.type = type;
        if (os_platform) params["os.platform"] = os_platform;
        if (tamperProtectionEnabled !== void 0) {
          params.tamperProtectionEnabled = tamperProtectionEnabled;
        }
        if (isolationStatus) params["isolation.status"] = isolationStatus;
        if (groupId) params.groupId = groupId;
        if (lastSeenBefore) params.lastSeenBefore = lastSeenBefore;
        if (lastSeenAfter) params.lastSeenAfter = lastSeenAfter;
        const response = await client.getEndpoints(params);
        const result = {
          endpoints: response.items.map((ep) => ({
            id: ep.id,
            hostname: ep.hostname,
            type: ep.type,
            health: ep.health.overall,
            os: `${ep.os.name} (${ep.os.platform})`,
            ipv4Addresses: ep.ipv4Addresses,
            lastSeenAt: ep.lastSeenAt,
            online: ep.online,
            tamperProtection: ep.tamperProtectionEnabled ? "enabled" : "disabled",
            isolation: ep.isolation?.status || "notIsolated",
            group: ep.group?.name,
            assignedProducts: ep.assignedProducts.map((p) => p.name).join(", "),
            associatedPerson: ep.associatedPerson?.name
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_endpoint",
    "Get full details of a specific Sophos Central endpoint including health status, assigned products, tamper protection, isolation state, and associated person",
    {
      endpoint_id: z.string().describe("Endpoint UUID")
    },
    async ({ endpoint_id }) => {
      try {
        const ep = await client.getEndpoint(endpoint_id);
        const result = {
          id: ep.id,
          hostname: ep.hostname,
          type: ep.type,
          health: {
            overall: ep.health.overall,
            threats: ep.health.threats.status,
            services: ep.health.services.status,
            serviceDetails: ep.health.services.serviceDetails
          },
          os: {
            platform: ep.os.platform,
            name: ep.os.name,
            majorVersion: ep.os.majorVersion,
            minorVersion: ep.os.minorVersion,
            build: ep.os.build,
            isServer: ep.os.isServer
          },
          ipv4Addresses: ep.ipv4Addresses,
          ipv6Addresses: ep.ipv6Addresses,
          macAddresses: ep.macAddresses,
          lastSeenAt: ep.lastSeenAt,
          firstSeenAt: ep.firstSeenAt,
          online: ep.online,
          tamperProtectionEnabled: ep.tamperProtectionEnabled,
          lockdown: ep.lockdown,
          isolation: ep.isolation || { status: "notIsolated" },
          group: ep.group,
          cloud: ep.cloud,
          associatedPerson: ep.associatedPerson,
          assignedProducts: ep.assignedProducts.map((p) => ({
            name: p.name,
            status: p.status,
            version: p.version
          })),
          tenantId: ep.tenant.id
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "isolate_endpoint",
    "Network isolate a Sophos Central endpoint for incident response \u2014 the endpoint can only communicate with Sophos Central",
    {
      endpoint_id: z.string().describe("Endpoint UUID to isolate"),
      comment: z.string().optional().describe("Reason for isolating the endpoint")
    },
    async ({ endpoint_id, comment }) => {
      try {
        const result = await client.isolateEndpoint(endpoint_id, comment);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...result,
                  message: `Endpoint ${endpoint_id} has been network isolated. It can only communicate with Sophos Central.`,
                  warning: "The endpoint is now disconnected from the network. Use unisolate_endpoint to restore connectivity."
                },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "unisolate_endpoint",
    "Remove network isolation from a Sophos Central endpoint, restoring normal network connectivity",
    {
      endpoint_id: z.string().describe("Endpoint UUID to unisolate"),
      comment: z.string().optional().describe("Reason for removing isolation")
    },
    async ({ endpoint_id, comment }) => {
      try {
        const result = await client.unisolateEndpoint(endpoint_id, comment);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...result,
                  message: `Network isolation removed from endpoint ${endpoint_id}. Normal connectivity restored.`
                },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "scan_endpoint",
    "Trigger a full on-demand antivirus scan on a Sophos Central endpoint",
    {
      endpoint_id: z.string().describe("Endpoint UUID to scan")
    },
    async ({ endpoint_id }) => {
      try {
        const result = await client.scanEndpoint(endpoint_id);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...result,
                  message: `Full scan initiated on endpoint ${endpoint_id}. Check endpoint events for scan results.`
                },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_endpoint_software",
    "List installed software on a Sophos Central endpoint \u2014 useful for vulnerability assessment and software inventory",
    {
      endpoint_id: z.string().describe("Endpoint UUID"),
      search: z.string().optional().describe("Search by software name or publisher"),
      pageSize: z.number().int().min(1).max(200).default(100).describe("Number of results to return (1-200)"),
      page: z.number().int().min(1).default(1).describe("Page number")
    },
    async ({ endpoint_id, search, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (search) params.search = search;
        const response = await client.getEndpointSoftware(endpoint_id, params);
        const result = {
          endpoint_id,
          software: response.items.map((sw) => ({
            name: sw.name,
            version: sw.version,
            publisher: sw.publisher,
            installDate: sw.installDate,
            size: sw.size
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/tools/alerts.ts
import { z as z2 } from "zod";
function registerAlertTools(server, client) {
  server.tool(
    "list_alerts",
    "List Sophos Central alerts with optional filters for severity, category, product, and date range",
    {
      severity: z2.enum(["low", "medium", "high"]).optional().describe("Filter by alert severity"),
      category: z2.string().optional().describe(
        "Filter by alert category (e.g., malware, pua, runtimeDetections, policy, protection, general)"
      ),
      product: z2.enum([
        "endpoint",
        "server",
        "mobile",
        "encryption",
        "emailGateway",
        "webGateway",
        "phishThreat",
        "wireless",
        "iaas",
        "firewall"
      ]).optional().describe("Filter by Sophos product that generated the alert"),
      from: z2.string().optional().describe("Return alerts raised after this ISO 8601 timestamp"),
      to: z2.string().optional().describe("Return alerts raised before this ISO 8601 timestamp"),
      pageSize: z2.number().int().min(1).max(100).default(25).describe("Number of results to return (1-100)"),
      page: z2.number().int().min(1).default(1).describe("Page number")
    },
    async ({ severity, category, product, from, to, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (severity) params.severity = severity;
        if (category) params.category = category;
        if (product) params.product = product;
        if (from) params.from = from;
        if (to) params.to = to;
        const response = await client.getAlerts(params);
        const result = {
          alerts: response.items.map((alert) => ({
            id: alert.id,
            severity: alert.severity,
            category: alert.category,
            type: alert.type,
            description: alert.description,
            product: alert.product,
            raisedAt: alert.raisedAt,
            managedAgent: alert.managedAgent ? {
              id: alert.managedAgent.id,
              type: alert.managedAgent.type,
              name: alert.managedAgent.name
            } : void 0,
            person: alert.person?.name,
            allowedActions: alert.allowedActions
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_alert",
    "Get full details of a specific Sophos Central alert including description, managed agent info, and available response actions",
    {
      alert_id: z2.string().describe("Alert UUID")
    },
    async ({ alert_id }) => {
      try {
        const alert = await client.getAlert(alert_id);
        const result = {
          id: alert.id,
          severity: alert.severity,
          category: alert.category,
          type: alert.type,
          description: alert.description,
          groupKey: alert.groupKey,
          product: alert.product,
          raisedAt: alert.raisedAt,
          managedAgent: alert.managedAgent,
          person: alert.person,
          tenant: alert.tenant,
          allowedActions: alert.allowedActions,
          data: alert.data
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "acknowledge_alert",
    "Acknowledge a Sophos Central alert \u2014 marks it as reviewed without resolving it",
    {
      alert_id: z2.string().describe("Alert UUID to acknowledge"),
      message: z2.string().optional().describe("Optional note or reason for acknowledgment")
    },
    async ({ alert_id, message }) => {
      try {
        const result = await client.performAlertAction(
          alert_id,
          "acknowledge",
          message
        );
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...result,
                  message: `Alert ${alert_id} acknowledged successfully.`
                },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "resolve_alert",
    "Resolve and close a Sophos Central alert with a description of the action taken",
    {
      alert_id: z2.string().describe("Alert UUID to resolve"),
      action: z2.enum(["cleanPua", "clean", "authPua", "clearThreat", "clearHmpa", "sendMsgPua", "sendMsgThreat"]).describe(
        "Resolution action: cleanPua (clean PUA), clean (clean threat), authPua (authorize PUA), clearThreat (clear threat), clearHmpa (clear HMPA), sendMsgPua (send message for PUA), sendMsgThreat (send message for threat)"
      ),
      message: z2.string().optional().describe("Description of the remediation action taken")
    },
    async ({ alert_id, action, message }) => {
      try {
        const result = await client.performAlertAction(alert_id, action, message);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...result,
                  message: `Alert ${alert_id} resolved with action '${action}'.`
                },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_alert_actions",
    "List available response actions for a specific Sophos Central alert \u2014 determines what actions can be performed",
    {
      alert_id: z2.string().describe("Alert UUID")
    },
    async ({ alert_id }) => {
      try {
        const alert = await client.getAlert(alert_id);
        const actionDescriptions = {
          acknowledge: "Mark the alert as reviewed without taking action",
          cleanPua: "Clean the Potentially Unwanted Application",
          clean: "Clean/remove the detected threat",
          authPua: "Authorize the PUA (allow it to run)",
          clearThreat: "Clear the threat alert",
          clearHmpa: "Clear the HMPA (behavioral) detection alert",
          sendMsgPua: "Send a message to the endpoint about the PUA",
          sendMsgThreat: "Send a message to the endpoint about the threat",
          contactSupport: "Escalate to Sophos support"
        };
        const result = {
          alert_id,
          severity: alert.severity,
          category: alert.category,
          allowedActions: alert.allowedActions.map((action) => ({
            action,
            description: actionDescriptions[action] || `Perform '${action}' action`
          })),
          actionCount: alert.allowedActions.length
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/tools/detections.ts
import { z as z3 } from "zod";
function registerDetectionTools(server, client) {
  server.tool(
    "list_detections",
    "List Sophos EDR/XDR detections with optional filters for severity, type, endpoint, and date range",
    {
      severity: z3.enum(["critical", "high", "medium", "low", "info"]).optional().describe("Filter by detection severity"),
      type: z3.string().optional().describe(
        "Filter by detection type (e.g., malwareExecution, behavioralExecution, exploitPrevention, lateralMovement, commandAndControl, credential, evasion)"
      ),
      endpointId: z3.string().optional().describe("Filter detections for a specific endpoint ID"),
      from: z3.string().optional().describe("Return detections after this ISO 8601 timestamp"),
      to: z3.string().optional().describe("Return detections before this ISO 8601 timestamp"),
      mitreTechnique: z3.string().optional().describe("Filter by MITRE ATT&CK technique ID (e.g., T1059.001)"),
      pageSize: z3.number().int().min(1).max(100).default(25).describe("Number of results to return (1-100)"),
      page: z3.number().int().min(1).default(1).describe("Page number")
    },
    async ({
      severity,
      type,
      endpointId,
      from,
      to,
      mitreTechnique,
      pageSize,
      page
    }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (severity) params.severity = severity;
        if (type) params.type = type;
        if (endpointId) params.endpointId = endpointId;
        if (from) params.from = from;
        if (to) params.to = to;
        if (mitreTechnique) params.mitreTechnique = mitreTechnique;
        const response = await client.getDetections(params);
        const result = {
          detections: response.items.map((det) => ({
            id: det.id,
            type: det.type,
            severity: det.severity,
            summary: det.summary,
            detectedAt: det.detectedAt,
            resolvedAt: det.resolvedAt,
            endpoint: {
              id: det.endpoint.id,
              hostname: det.endpoint.hostname,
              os: det.endpoint.os
            },
            process: det.process ? {
              name: det.process.name,
              path: det.process.path,
              sha256: det.process.sha256
            } : void 0,
            user: det.user?.name,
            mitreTechniques: det.mitreTechniques.map((t) => ({
              id: t.id,
              name: t.name,
              tactics: t.tactics
            })),
            indicatorCount: det.indicators.length
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_detection",
    "Get full details of a Sophos EDR/XDR detection including process tree, MITRE ATT&CK mapping, indicators, and raw event data",
    {
      detection_id: z3.string().describe("Detection UUID")
    },
    async ({ detection_id }) => {
      try {
        const det = await client.getDetection(detection_id);
        const result = {
          id: det.id,
          type: det.type,
          severity: det.severity,
          summary: det.summary,
          description: det.description,
          detectedAt: det.detectedAt,
          resolvedAt: det.resolvedAt,
          endpoint: det.endpoint,
          process: det.process ? {
            pid: det.process.pid,
            name: det.process.name,
            path: det.process.path,
            commandLine: det.process.commandLine,
            sha256: det.process.sha256,
            parentPid: det.process.parentPid,
            parentName: det.process.parentName
          } : void 0,
          user: det.user,
          mitreTechniques: det.mitreTechniques.map((t) => ({
            id: t.id,
            name: t.name,
            tactics: t.tactics,
            url: t.url
          })),
          indicators: det.indicators.map((ind) => ({
            type: ind.type,
            value: ind.value,
            description: ind.description
          })),
          rawData: det.rawData
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_threat_cases",
    "List Sophos threat cases \u2014 groups of related EDR/XDR detections that form a single incident narrative",
    {
      status: z3.enum(["new", "investigating", "inProgress", "containment", "resolved", "closed"]).optional().describe("Filter by threat case status"),
      severity: z3.enum(["critical", "high", "medium", "low", "info"]).optional().describe("Filter by severity"),
      from: z3.string().optional().describe("Return cases created after this ISO 8601 timestamp"),
      to: z3.string().optional().describe("Return cases created before this ISO 8601 timestamp"),
      pageSize: z3.number().int().min(1).max(100).default(25).describe("Number of results to return (1-100)"),
      page: z3.number().int().min(1).default(1).describe("Page number")
    },
    async ({ status, severity, from, to, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (status) params.status = status;
        if (severity) params.severity = severity;
        if (from) params.from = from;
        if (to) params.to = to;
        const response = await client.getThreatCases(params);
        const result = {
          threatCases: response.items.map((tc) => ({
            id: tc.id,
            name: tc.name,
            status: tc.status,
            severity: tc.severity,
            description: tc.description,
            createdAt: tc.createdAt,
            updatedAt: tc.updatedAt,
            assignee: tc.assignee?.name,
            detectionCount: tc.detectionCount,
            endpointCount: tc.endpointCount,
            mitreTechniques: tc.mitreTechniques.map((t) => `${t.id} (${t.name})`)
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_case_detections",
    "Get all detections within a Sophos threat case \u2014 shows every detection that contributed to the case",
    {
      case_id: z3.string().describe("Threat case UUID"),
      pageSize: z3.number().int().min(1).max(100).default(50).describe("Number of results to return (1-100)"),
      page: z3.number().int().min(1).default(1).describe("Page number")
    },
    async ({ case_id, pageSize, page }) => {
      try {
        const response = await client.getCaseDetections(case_id, {
          pageSize,
          page
        });
        const result = {
          caseId: case_id,
          detections: response.items.map((det) => ({
            id: det.id,
            type: det.type,
            severity: det.severity,
            summary: det.summary,
            detectedAt: det.detectedAt,
            endpoint: {
              hostname: det.endpoint.hostname,
              id: det.endpoint.id
            },
            process: det.process ? {
              name: det.process.name,
              path: det.process.path,
              commandLine: det.process.commandLine
            } : void 0,
            user: det.user?.name,
            mitreTechniques: det.mitreTechniques.map((t) => t.id)
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "update_case_status",
    "Update the status of a Sophos threat case and optionally assign it to an analyst",
    {
      case_id: z3.string().describe("Threat case UUID"),
      status: z3.enum(["new", "investigating", "inProgress", "containment", "resolved", "closed"]).describe("New status for the threat case"),
      assignee_id: z3.string().optional().describe("User ID to assign the case to")
    },
    async ({ case_id, status, assignee_id }) => {
      try {
        const tc = await client.updateCaseStatus(case_id, status, assignee_id);
        const result = {
          id: tc.id,
          name: tc.name,
          status: tc.status,
          severity: tc.severity,
          assignee: tc.assignee?.name,
          updatedAt: tc.updatedAt,
          message: `Threat case ${case_id} updated to status '${status}'.`
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/tools/events.ts
import { z as z4 } from "zod";
function registerEventTools(server, client) {
  server.tool(
    "search_events",
    "Search Sophos Central security events by type, severity, endpoint, source, and date range \u2014 the primary SIEM event feed",
    {
      type: z4.string().optional().describe(
        "Filter by event type (e.g., Event::Endpoint::Threat::Detected, Event::Endpoint::WebFilteringBlocked, Event::Endpoint::Threat::CleanedUp, Event::Firewall::Blocked)"
      ),
      severity: z4.enum(["none", "low", "medium", "high", "critical"]).optional().describe("Filter by event severity"),
      endpointId: z4.string().optional().describe("Filter events for a specific endpoint ID"),
      sourceType: z4.string().optional().describe("Filter by event source (e.g., antivirus, deviceControl, firewall)"),
      from: z4.string().optional().describe("Return events after this ISO 8601 timestamp"),
      to: z4.string().optional().describe("Return events before this ISO 8601 timestamp"),
      search: z4.string().optional().describe("Full-text search across event name and location"),
      pageSize: z4.number().int().min(1).max(200).default(50).describe("Number of results to return (1-200)"),
      page: z4.number().int().min(1).default(1).describe("Page number")
    },
    async ({
      type,
      severity,
      endpointId,
      sourceType,
      from,
      to,
      search,
      pageSize,
      page
    }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (type) params.type = type;
        if (severity) params.severity = severity;
        if (endpointId) params.endpointId = endpointId;
        if (sourceType) params.source = sourceType;
        if (from) params.from = from;
        if (to) params.to = to;
        if (search) params.search = search;
        const response = await client.getEvents(params);
        const result = {
          events: response.items.map((evt) => ({
            id: evt.id,
            type: evt.type,
            severity: evt.severity,
            name: evt.name,
            location: evt.location,
            group: evt.group,
            when: evt.when,
            source: evt.source,
            endpoint: evt.endpoint ? {
              id: evt.endpoint.id,
              hostname: evt.endpoint.hostname,
              type: evt.endpoint.type
            } : void 0,
            user: evt.user?.name,
            ioc: evt.ioc,
            iocType: evt.iocType
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_event",
    "Get full details of a specific Sophos Central security event including customer data, IOCs, and endpoint context",
    {
      event_id: z4.string().describe("Event UUID")
    },
    async ({ event_id }) => {
      try {
        const evt = await client.getEvent(event_id);
        const result = {
          id: evt.id,
          type: evt.type,
          severity: evt.severity,
          name: evt.name,
          location: evt.location,
          group: evt.group,
          when: evt.when,
          source: evt.source,
          endpoint: evt.endpoint,
          user: evt.user,
          customerData: evt.customerData,
          ioc: evt.ioc,
          iocType: evt.iocType
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "list_event_types",
    "List available Sophos Central security event types and their descriptions \u2014 useful for building event search queries",
    {},
    async () => {
      try {
        const eventTypes = [
          {
            type: "Event::Endpoint::Threat::Detected",
            description: "Malware or threat detected on an endpoint",
            severity: "high",
            source: "antivirus"
          },
          {
            type: "Event::Endpoint::Threat::CleanedUp",
            description: "Detected threat was successfully cleaned/removed",
            severity: "low",
            source: "antivirus"
          },
          {
            type: "Event::Endpoint::Threat::NotBlocked",
            description: "Threat detected but could not be blocked automatically",
            severity: "critical",
            source: "antivirus"
          },
          {
            type: "Event::Endpoint::Threat::PuaDetected",
            description: "Potentially Unwanted Application detected",
            severity: "medium",
            source: "antivirus"
          },
          {
            type: "Event::Endpoint::Threat::PuaCleanedUp",
            description: "PUA was successfully cleaned/removed",
            severity: "low",
            source: "antivirus"
          },
          {
            type: "Event::Endpoint::Application::Blocked",
            description: "Application blocked by application control policy",
            severity: "medium",
            source: "applicationControl"
          },
          {
            type: "Event::Endpoint::DataLossPrevention",
            description: "Data loss prevention rule triggered",
            severity: "high",
            source: "dlp"
          },
          {
            type: "Event::Endpoint::WebControlViolation",
            description: "Web control policy violation (category-based blocking)",
            severity: "medium",
            source: "webControl"
          },
          {
            type: "Event::Endpoint::WebFilteringBlocked",
            description: "Malicious or phishing website blocked",
            severity: "high",
            source: "webFiltering"
          },
          {
            type: "Event::Endpoint::UpdateSuccess",
            description: "Endpoint agent updated successfully",
            severity: "none",
            source: "updating"
          },
          {
            type: "Event::Endpoint::UpdateFailure",
            description: "Endpoint agent update failed",
            severity: "medium",
            source: "updating"
          },
          {
            type: "Event::Endpoint::SavScanComplete",
            description: "Scheduled or on-demand scan completed",
            severity: "none",
            source: "antivirus"
          },
          {
            type: "Event::Endpoint::CoreRestore::Failed",
            description: "Endpoint core component restore failed",
            severity: "high",
            source: "core"
          },
          {
            type: "Event::Firewall::Allowed",
            description: "Network traffic allowed by firewall policy",
            severity: "none",
            source: "firewall"
          },
          {
            type: "Event::Firewall::Blocked",
            description: "Network traffic blocked by firewall policy",
            severity: "medium",
            source: "firewall"
          },
          {
            type: "Event::Mobile::ComplianceViolation",
            description: "Mobile device compliance policy violation",
            severity: "medium",
            source: "mobile"
          }
        ];
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { eventTypes, total: eventTypes.length },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_audit_logs",
    "Get the admin audit trail from Sophos Central \u2014 tracks all administrative actions including policy changes, user management, and configuration updates",
    {
      actorType: z4.enum(["user", "system", "api"]).optional().describe("Filter by actor type"),
      from: z4.string().optional().describe("Return audit events after this ISO 8601 timestamp"),
      to: z4.string().optional().describe("Return audit events before this ISO 8601 timestamp"),
      search: z4.string().optional().describe("Search by actor name, description, or target name"),
      pageSize: z4.number().int().min(1).max(200).default(50).describe("Number of results to return (1-200)"),
      page: z4.number().int().min(1).default(1).describe("Page number")
    },
    async ({ actorType, from, to, search, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (actorType) params["actor.type"] = actorType;
        if (from) params.from = from;
        if (to) params.to = to;
        if (search) params.search = search;
        const response = await client.getAuditLogs(params);
        const result = {
          auditLogs: response.items.map((log) => ({
            id: log.id,
            type: log.type,
            description: log.description,
            timestamp: log.timestamp,
            actor: {
              name: log.actor.name,
              type: log.actor.type
            },
            target: log.target ? {
              name: log.target.name,
              type: log.target.type
            } : void 0,
            result: log.result,
            sourceIp: log.sourceIp
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/tools/policies.ts
import { z as z5 } from "zod";
function registerPolicyTools(server, client) {
  server.tool(
    "list_policies",
    "List Sophos Central endpoint, server, and firewall policies with optional type filter",
    {
      type: z5.enum([
        "threat-protection",
        "peripheral-control",
        "application-control",
        "data-loss-prevention",
        "tamper-protection",
        "web-control",
        "windows-firewall",
        "server-threat-protection",
        "server-peripheral-control",
        "server-lockdown",
        "server-application-control",
        "update-management"
      ]).optional().describe("Filter by policy type"),
      enabled: z5.boolean().optional().describe("Filter by enabled/disabled state"),
      pageSize: z5.number().int().min(1).max(100).default(50).describe("Number of results to return (1-100)"),
      page: z5.number().int().min(1).default(1).describe("Page number")
    },
    async ({ type, enabled, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (type) params.type = type;
        if (enabled !== void 0) params.enabled = enabled;
        const response = await client.getPolicies(params);
        const result = {
          policies: response.items.map((pol) => ({
            id: pol.id,
            name: pol.name,
            type: pol.type,
            enabled: pol.enabled,
            enforcement: pol.enforcement,
            priority: pol.priority,
            appliesTo: pol.appliesTo,
            createdAt: pol.createdAt,
            updatedAt: pol.updatedAt,
            lockedBy: pol.lockedBy
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_policy",
    "Get full configuration details of a specific Sophos Central policy including all settings and scope",
    {
      policy_id: z5.string().describe("Policy UUID")
    },
    async ({ policy_id }) => {
      try {
        const pol = await client.getPolicy(policy_id);
        const result = {
          id: pol.id,
          name: pol.name,
          type: pol.type,
          enabled: pol.enabled,
          enforcement: pol.enforcement,
          priority: pol.priority,
          settings: pol.settings,
          appliesTo: pol.appliesTo,
          createdAt: pol.createdAt,
          updatedAt: pol.updatedAt,
          lockedBy: pol.lockedBy
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_policy_settings",
    "Get specific settings within a Sophos Central policy \u2014 extracts and formats individual configuration sections for easier analysis",
    {
      policy_id: z5.string().describe("Policy UUID"),
      setting_key: z5.string().optional().describe(
        "Specific setting key to retrieve (e.g., 'malwareProtection', 'webControl', 'fileProtection'). If omitted, returns all settings."
      )
    },
    async ({ policy_id, setting_key }) => {
      try {
        const pol = await client.getPolicy(policy_id);
        let settingsToReturn;
        if (setting_key) {
          const value = pol.settings[setting_key];
          if (value === void 0) {
            const availableKeys = Object.keys(pol.settings);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      error: `Setting '${setting_key}' not found in policy '${pol.name}'.`,
                      availableSettings: availableKeys
                    },
                    null,
                    2
                  )
                }
              ],
              isError: true
            };
          }
          settingsToReturn = { [setting_key]: value };
        } else {
          settingsToReturn = pol.settings;
        }
        const result = {
          policyId: pol.id,
          policyName: pol.name,
          policyType: pol.type,
          enforcement: pol.enforcement,
          settings: settingsToReturn,
          availableSettingKeys: Object.keys(pol.settings)
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "list_exclusions",
    "List global and policy-specific scanning exclusions in Sophos Central \u2014 important for security audits and troubleshooting false positives",
    {
      type: z5.enum(["path", "process", "extension", "posixPath", "virtualPath", "amsi"]).optional().describe("Filter by exclusion type"),
      search: z5.string().optional().describe("Search exclusions by value or description"),
      pageSize: z5.number().int().min(1).max(200).default(100).describe("Number of results to return (1-200)"),
      page: z5.number().int().min(1).default(1).describe("Page number")
    },
    async ({ type, search, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (type) params.type = type;
        if (search) params.search = search;
        const response = await client.getExclusions(params);
        const result = {
          exclusions: response.items.map((exc) => ({
            id: exc.id,
            type: exc.type,
            value: exc.value,
            description: exc.description,
            scanMode: exc.scanMode,
            comment: exc.comment
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/tools/tenants.ts
import { z as z6 } from "zod";
function registerTenantTools(server, client) {
  server.tool(
    "list_tenants",
    "List managed tenants in Sophos Central \u2014 MSP/partner view of all managed organizations with status and billing info",
    {
      status: z6.enum(["active", "deactivated", "suspended"]).optional().describe("Filter by tenant status"),
      search: z6.string().optional().describe("Search by tenant name"),
      pageSize: z6.number().int().min(1).max(100).default(50).describe("Number of results to return (1-100)"),
      page: z6.number().int().min(1).default(1).describe("Page number")
    },
    async ({ status, search, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (status) params.status = status;
        if (search) params.search = search;
        const response = await client.getTenants(params);
        const result = {
          tenants: response.items.map((t) => ({
            id: t.id,
            name: t.name,
            status: t.status,
            billingType: t.billingType,
            dataGeography: t.dataGeography,
            dataRegion: t.dataRegion,
            createdAt: t.createdAt,
            contact: t.contact ? {
              name: `${t.contact.firstName} ${t.contact.lastName}`,
              email: t.contact.email
            } : void 0,
            licenseCount: t.licenses.length,
            activeLicenses: t.licenses.filter((l) => l.status === "active").map((l) => l.product)
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_tenant",
    "Get full details of a managed tenant including contact info, license details, and data region",
    {
      tenant_id: z6.string().describe("Tenant UUID")
    },
    async ({ tenant_id }) => {
      try {
        const t = await client.getTenant(tenant_id);
        const result = {
          id: t.id,
          name: t.name,
          status: t.status,
          billingType: t.billingType,
          dataGeography: t.dataGeography,
          dataRegion: t.dataRegion,
          apiHost: t.apiHost,
          createdAt: t.createdAt,
          contact: t.contact ? {
            firstName: t.contact.firstName,
            lastName: t.contact.lastName,
            email: t.contact.email,
            phone: t.contact.phone
          } : void 0,
          licenses: t.licenses.map((l) => ({
            id: l.id,
            product: l.product,
            type: l.type,
            quantity: l.quantity,
            usedQuantity: l.usedQuantity,
            available: l.quantity - l.usedQuantity,
            expiresAt: l.expiresAt,
            status: l.status
          }))
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_tenant_health",
    "Get overall security health score for a tenant \u2014 endpoint protection coverage, active threats, and compliance metrics",
    {
      tenant_id: z6.string().describe("Tenant UUID")
    },
    async ({ tenant_id }) => {
      try {
        const [endpointsResp, alertsResp] = await Promise.all([
          client.getEndpoints({ pageSize: 1 }),
          client.getAlerts({ pageSize: 1 })
        ]);
        const totalEndpoints = endpointsResp.pages.items;
        const totalAlerts = alertsResp.pages.items;
        const healthScore = Math.max(
          0,
          100 - totalAlerts * 2
        );
        const result = {
          tenantId: tenant_id,
          endpointCount: totalEndpoints,
          activeAlerts: totalAlerts,
          healthScore: Math.min(100, healthScore),
          healthRating: healthScore >= 90 ? "excellent" : healthScore >= 70 ? "good" : healthScore >= 50 ? "fair" : "poor",
          summary: `Tenant has ${totalEndpoints} managed endpoints with ${totalAlerts} active alerts. Health score: ${Math.min(100, healthScore)}/100.`,
          recommendations: totalAlerts > 10 ? [
            "Review and triage active alerts immediately",
            "Investigate high-severity alerts first",
            "Check for unprotected or unhealthy endpoints",
            "Verify tamper protection is enabled across all endpoints"
          ] : totalAlerts > 0 ? [
            "Continue monitoring active alerts",
            "Ensure all endpoints have up-to-date protection"
          ] : ["All clear \u2014 maintain regular monitoring schedule"]
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/tools/live-discover.ts
import { z as z7 } from "zod";
function registerLiveDiscoverTools(server, client) {
  server.tool(
    "run_query",
    "Execute a Live Discover SQL query (osquery) on one or more Sophos Central endpoints \u2014 for real-time investigation and threat hunting",
    {
      sql: z7.string().describe(
        "SQL query to execute on endpoints (osquery syntax). Example: SELECT pid, name, path FROM processes WHERE name LIKE '%suspicious%'"
      ),
      endpoint_ids: z7.array(z7.string()).min(1).max(50).describe("Array of endpoint UUIDs to run the query on (1-50 endpoints)"),
      variables: z7.record(z7.string()).optional().describe("Query variables as key-value pairs for parameterized queries")
    },
    async ({ sql, endpoint_ids, variables }) => {
      try {
        const queryRun = await client.runLiveDiscoverQuery(
          sql,
          endpoint_ids,
          variables
        );
        const result = {
          queryRunId: queryRun.id,
          sql: queryRun.sql,
          status: queryRun.status,
          endpointCount: queryRun.endpoints.length,
          endpoints: queryRun.endpoints.map((ep) => ({
            id: ep.id,
            hostname: ep.hostname,
            status: ep.status
          })),
          createdAt: queryRun.createdAt,
          message: queryRun.status === "finished" ? `Query completed. Use get_query_results with queryRunId '${queryRun.id}' to retrieve results.` : `Query submitted (status: ${queryRun.status}). Poll get_query_results with queryRunId '${queryRun.id}' for results.`
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "list_saved_queries",
    "List saved Live Discover queries in Sophos Central \u2014 includes built-in and custom queries with their SQL and supported platforms",
    {
      category: z7.enum([
        "processes",
        "network",
        "filesystem",
        "registry",
        "users",
        "services",
        "hardware",
        "software",
        "security",
        "general",
        "custom"
      ]).optional().describe("Filter by query category"),
      search: z7.string().optional().describe("Search by query name or description"),
      builtIn: z7.boolean().optional().describe("Filter by built-in (true) or custom (false) queries"),
      pageSize: z7.number().int().min(1).max(100).default(50).describe("Number of results to return (1-100)"),
      page: z7.number().int().min(1).default(1).describe("Page number")
    },
    async ({ category, search, builtIn, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (category) params.category = category;
        if (search) params.search = search;
        if (builtIn !== void 0) params.builtIn = builtIn;
        const response = await client.getSavedQueries(params);
        const result = {
          queries: response.items.map((q) => ({
            id: q.id,
            name: q.name,
            description: q.description,
            category: q.category,
            sql: q.sql,
            supportedOSes: q.supportedOSes,
            variables: q.variables,
            builtIn: q.builtIn,
            createdAt: q.createdAt
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "get_query_results",
    "Retrieve results from a completed Live Discover query run \u2014 returns tabular data from each endpoint",
    {
      query_run_id: z7.string().describe("Query run UUID returned by run_query"),
      endpoint_id: z7.string().optional().describe("Filter results for a specific endpoint ID"),
      pageSize: z7.number().int().min(1).max(500).default(100).describe("Number of result rows to return (1-500)"),
      page: z7.number().int().min(1).default(1).describe("Page number")
    },
    async ({ query_run_id, endpoint_id, pageSize, page }) => {
      try {
        const params = {
          pageSize,
          page
        };
        if (endpoint_id) params.endpointId = endpoint_id;
        const response = await client.getQueryResults(query_run_id, params);
        const result = {
          queryRunId: query_run_id,
          status: response.status,
          results: response.items.map((r) => ({
            endpointId: r.endpointId,
            hostname: r.hostname,
            columns: r.columns,
            rowCount: r.rows.length,
            rows: r.rows
          })),
          endpointCount: response.items.length,
          totalRows: response.items.reduce((sum, r) => sum + r.rows.length, 0)
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
  server.tool(
    "list_query_categories",
    "List available Live Discover query categories with descriptions and example queries \u2014 helps discover what you can query",
    {},
    async () => {
      try {
        const categories = [
          {
            category: "processes",
            description: "Running processes, process trees, and execution history",
            exampleQueries: [
              "SELECT pid, name, path, cmdline, start_time, uid FROM processes ORDER BY start_time DESC LIMIT 50",
              "SELECT pid, name, path, cmdline FROM processes WHERE name = '$$processName$$'",
              "SELECT p.pid, p.name, p.path, p.cmdline, pp.name AS parent_name FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid"
            ]
          },
          {
            category: "network",
            description: "Network connections, listening ports, DNS cache, ARP table",
            exampleQueries: [
              "SELECT pid, remote_address, remote_port, local_port, state, protocol FROM process_open_sockets WHERE remote_address != '' AND remote_address != '127.0.0.1'",
              "SELECT pid, port, address, protocol FROM listening_ports WHERE port NOT IN (80, 443, 22)",
              "SELECT pid, remote_address, remote_port, state FROM socket_events WHERE remote_port = 4444"
            ]
          },
          {
            category: "filesystem",
            description: "File metadata, hashes, recently modified files, downloads",
            exampleQueries: [
              "SELECT path, filename, size, mtime, sha256 FROM hash WHERE path = '$$filePath$$'",
              "SELECT path, filename, size, mtime FROM file WHERE directory = '$$directory$$'",
              "SELECT path, sha256 FROM hash WHERE path LIKE '/tmp/%' AND sha256 != ''"
            ]
          },
          {
            category: "registry",
            description: "Windows registry keys and values (persistence, configuration)",
            exampleQueries: [
              "SELECT path, name, data, type FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'",
              "SELECT path, name, data FROM registry WHERE key LIKE '%\\CurrentVersion\\Run%'"
            ]
          },
          {
            category: "users",
            description: "User accounts, login history, group memberships",
            exampleQueries: [
              "SELECT uid, gid, username, directory, shell FROM users",
              "SELECT username, tty, host, time, type FROM last WHERE type = 7 ORDER BY time DESC LIMIT 20",
              "SELECT * FROM logged_in_users"
            ]
          },
          {
            category: "services",
            description: "System services, startup items, scheduled tasks",
            exampleQueries: [
              "SELECT name, display_name, status, start_type, path FROM services WHERE start_type = 'AUTO_START'",
              "SELECT name, action, path, enabled, next_run_time FROM scheduled_tasks WHERE enabled = 1",
              "SELECT name, path, args FROM startup_items"
            ]
          },
          {
            category: "hardware",
            description: "Hardware info, USB devices, PCI devices",
            exampleQueries: [
              "SELECT vendor, model, serial, removable FROM usb_devices",
              "SELECT vendor_id, model_id, vendor, model FROM pci_devices",
              "SELECT hardware_vendor, hardware_model, cpu_brand, physical_memory FROM system_info"
            ]
          },
          {
            category: "software",
            description: "Installed software, browser extensions, packages",
            exampleQueries: [
              "SELECT name, version, publisher FROM programs ORDER BY name",
              "SELECT name, version, publisher FROM programs WHERE publisher LIKE '%unknown%'",
              "SELECT name, version, source FROM deb_packages UNION SELECT name, version, 'rpm' FROM rpm_packages"
            ]
          },
          {
            category: "security",
            description: "Security state, certificates, encryption, patches",
            exampleQueries: [
              "SELECT hotfix_id, description, installed_on FROM patches ORDER BY installed_on DESC LIMIT 20",
              "SELECT common_name, issuer, not_valid_after FROM certificates WHERE not_valid_after < datetime('now')",
              "SELECT encrypted, type, uuid FROM disk_encryption"
            ]
          },
          {
            category: "general",
            description: "System info, uptime, environment variables, OS version",
            exampleQueries: [
              "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info",
              "SELECT days, hours, minutes, total_seconds FROM uptime",
              "SELECT key, value FROM osquery_flags"
            ]
          }
        ];
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { categories, total: categories.length },
                null,
                2
              )
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error)
              })
            }
          ],
          isError: true
        };
      }
    }
  );
}

// src/resources/index.ts
function registerResources(server) {
  server.resource(
    "live-discover-queries",
    "sophos://live-discover-queries",
    {
      description: "Built-in Live Discover query library with osquery SQL templates for endpoint investigation, threat hunting, and forensic analysis",
      mimeType: "application/json"
    },
    async () => {
      const queries = [
        {
          name: "Running Processes",
          category: "processes",
          description: "List all running processes with details",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pid, name, path, cmdline, start_time, uid, on_disk, parent FROM processes ORDER BY start_time DESC"
        },
        {
          name: "Suspicious Process Names",
          category: "processes",
          description: "Find processes matching a suspicious name pattern",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pid, name, path, cmdline, start_time FROM processes WHERE name = '$$processName$$'",
          variables: [{ name: "processName", type: "string", description: "Process name to search for" }]
        },
        {
          name: "Process Tree",
          category: "processes",
          description: "Show parent-child process relationships",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT p.pid, p.name, p.path, p.cmdline, pp.pid AS parent_pid, pp.name AS parent_name, pp.path AS parent_path FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid WHERE p.name != ''"
        },
        {
          name: "Encoded PowerShell Commands",
          category: "processes",
          description: "Detect Base64 encoded PowerShell execution",
          os: ["windows"],
          sql: "SELECT pid, name, cmdline, start_time FROM processes WHERE name = 'powershell.exe' AND (cmdline LIKE '%-enc%' OR cmdline LIKE '%-EncodedCommand%' OR cmdline LIKE '%FromBase64String%')"
        },
        {
          name: "Listening Ports",
          category: "network",
          description: "Show all listening network ports with associated processes",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT lp.pid, p.name, lp.port, lp.address, lp.protocol FROM listening_ports lp JOIN processes p ON lp.pid = p.pid ORDER BY lp.port"
        },
        {
          name: "Non-Standard Listening Ports",
          category: "network",
          description: "Find unusual listening ports that may indicate backdoors",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT lp.pid, p.name, p.path, lp.port, lp.address, lp.protocol FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port NOT IN (80, 443, 22, 53, 135, 139, 445, 3389, 5985, 5986, 8080, 8443) ORDER BY lp.port"
        },
        {
          name: "Active Network Connections",
          category: "network",
          description: "Show current outbound connections with remote addresses",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pos.pid, p.name, pos.remote_address, pos.remote_port, pos.local_port, pos.state FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1' AND pos.remote_address != '::1'"
        },
        {
          name: "Connections to Suspicious Port",
          category: "network",
          description: "Find connections to a specific port (e.g., C2 port)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pos.pid, p.name, p.path, pos.remote_address, pos.remote_port, pos.state FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_port = $$port$$",
          variables: [{ name: "port", type: "integer", description: "Remote port to search for" }]
        },
        {
          name: "DNS Cache",
          category: "network",
          description: "Dump the local DNS resolver cache",
          os: ["windows"],
          sql: "SELECT name, type, answer FROM dns_cache ORDER BY name"
        },
        {
          name: "Scheduled Tasks",
          category: "services",
          description: "List all scheduled tasks with their actions",
          os: ["windows"],
          sql: "SELECT name, action, path, enabled, next_run_time, last_run_time FROM scheduled_tasks WHERE enabled = 1 ORDER BY next_run_time"
        },
        {
          name: "Autorun/Startup Items",
          category: "services",
          description: "Show all autorun and startup entries (persistence mechanisms)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT name, path, args, source FROM startup_items ORDER BY name"
        },
        {
          name: "Windows Services",
          category: "services",
          description: "List Windows services with their startup configuration",
          os: ["windows"],
          sql: "SELECT name, display_name, status, start_type, path, module_path, user_account FROM services ORDER BY name"
        },
        {
          name: "Recently Modified Files",
          category: "filesystem",
          description: "Find files modified within the last N hours in a directory",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT path, filename, size, mtime, atime FROM file WHERE directory = '$$directory$$' AND mtime > (strftime('%s', 'now') - $$hours$$ * 3600)",
          variables: [
            { name: "directory", type: "string", description: "Directory to search" },
            { name: "hours", type: "integer", description: "Hours to look back", defaultValue: "24" }
          ]
        },
        {
          name: "File Hash Lookup",
          category: "filesystem",
          description: "Get SHA256 hash of a specific file",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT path, sha256, md5 FROM hash WHERE path = '$$filePath$$'",
          variables: [{ name: "filePath", type: "string", description: "Full path to the file" }]
        },
        {
          name: "Temporary Directory Files",
          category: "filesystem",
          description: "List files in common temp directories that may contain malware",
          os: ["windows"],
          sql: "SELECT path, filename, size, mtime FROM file WHERE (directory LIKE 'C:\\Users\\%\\AppData\\Local\\Temp%' OR directory LIKE 'C:\\Windows\\Temp%') AND size > 0 ORDER BY mtime DESC LIMIT 100"
        },
        {
          name: "Installed Software",
          category: "software",
          description: "Complete list of installed software with versions",
          os: ["windows"],
          sql: "SELECT name, version, publisher, install_date FROM programs ORDER BY name"
        },
        {
          name: "Software by Unknown Publisher",
          category: "software",
          description: "Find software from unknown or suspicious publishers",
          os: ["windows"],
          sql: "SELECT name, version, publisher, install_date FROM programs WHERE publisher IS NULL OR publisher = '' OR publisher LIKE '%unknown%'"
        },
        {
          name: "Browser Extensions",
          category: "software",
          description: "List installed browser extensions (Chrome)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT ce.name, ce.identifier, ce.version, ce.description, ce.author, ce.path FROM chrome_extensions ce"
        },
        {
          name: "Run Key Persistence",
          category: "registry",
          description: "Check common Run key registry persistence locations",
          os: ["windows"],
          sql: "SELECT path, name, data, type FROM registry WHERE key IN ('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce')"
        },
        {
          name: "User Accounts",
          category: "users",
          description: "List all local user accounts",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT uid, gid, username, description, directory, shell, type FROM users"
        },
        {
          name: "Recent Logins",
          category: "users",
          description: "Show recent login events",
          os: ["linux", "macOS"],
          sql: "SELECT username, tty, host, time, type FROM last WHERE type = 7 ORDER BY time DESC LIMIT 50"
        },
        {
          name: "Currently Logged In Users",
          category: "users",
          description: "Show users with active sessions",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT user, tty, host, time, pid FROM logged_in_users"
        },
        {
          name: "USB Devices",
          category: "hardware",
          description: "List connected and recently connected USB devices",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT vendor, model, serial, removable, last_connection_time FROM usb_devices ORDER BY last_connection_time DESC"
        },
        {
          name: "System Information",
          category: "general",
          description: "Get comprehensive system information",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT hostname, cpu_brand, cpu_physical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial FROM system_info"
        },
        {
          name: "OS Version",
          category: "general",
          description: "Get detailed OS version information",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT name, version, major, minor, build, platform, codename, arch FROM os_version"
        },
        {
          name: "Disk Encryption Status",
          category: "security",
          description: "Check disk encryption status (BitLocker/FileVault/LUKS)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT name, uuid, encrypted, type, encryption_status FROM disk_encryption"
        },
        {
          name: "Missing Patches",
          category: "security",
          description: "List recently installed patches to identify missing updates",
          os: ["windows"],
          sql: "SELECT hotfix_id, description, installed_on, installed_by FROM patches ORDER BY installed_on DESC"
        },
        {
          name: "Expired Certificates",
          category: "security",
          description: "Find expired or soon-to-expire certificates",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT common_name, issuer, not_valid_after, not_valid_before, signing_algorithm FROM certificates WHERE not_valid_after < datetime('now', '+30 days') ORDER BY not_valid_after"
        }
      ];
      return {
        contents: [
          {
            uri: "sophos://live-discover-queries",
            mimeType: "application/json",
            text: JSON.stringify({ queries, total: queries.length }, null, 2)
          }
        ]
      };
    }
  );
  server.resource(
    "policy-reference",
    "sophos://policy-reference",
    {
      description: "Sophos Central policy settings reference \u2014 describes available policy types, their settings, and recommended configurations",
      mimeType: "application/json"
    },
    async () => {
      const policyReference = {
        policyTypes: [
          {
            type: "threat-protection",
            description: "Endpoint threat protection settings including real-time scanning, web protection, and behavior monitoring",
            settings: {
              realTimeScanning: {
                description: "Enable/disable real-time file scanning",
                recommended: true,
                options: ["on", "off"]
              },
              behaviorMonitoring: {
                description: "Monitor process behavior for suspicious activity",
                recommended: true,
                options: ["on", "off"]
              },
              webProtection: {
                description: "Block access to malicious websites",
                recommended: true,
                options: ["on", "off", "warn"]
              },
              amsiProtection: {
                description: "Anti-Malware Scan Interface integration",
                recommended: true,
                options: ["on", "off"]
              },
              intrusionPrevention: {
                description: "Network-level exploit prevention",
                recommended: true,
                options: ["on", "off"]
              },
              deepLearning: {
                description: "Deep learning malware detection model",
                recommended: true,
                options: ["on", "off"]
              },
              ransomwareProtection: {
                description: "CryptoGuard ransomware protection",
                recommended: true,
                options: ["on", "off"]
              },
              exploitPrevention: {
                description: "Exploit mitigation techniques",
                recommended: true,
                options: ["on", "off"]
              }
            }
          },
          {
            type: "peripheral-control",
            description: "Control access to USB devices, removable media, and peripherals",
            settings: {
              removableMedia: { description: "Control USB storage devices", options: ["allow", "block", "readOnly"] },
              mtp: { description: "Media Transfer Protocol devices", options: ["allow", "block"] },
              bluetooth: { description: "Bluetooth device control", options: ["allow", "block"] },
              infrared: { description: "Infrared device control", options: ["allow", "block"] },
              wireless: { description: "WiFi adapter control", options: ["allow", "block"] }
            }
          },
          {
            type: "application-control",
            description: "Block or allow specific applications by category or custom rules",
            settings: {
              controlledApplications: { description: "List of controlled application categories" },
              detection: { description: "Detect and report or block", options: ["detectOnly", "block"] }
            }
          },
          {
            type: "data-loss-prevention",
            description: "Protect sensitive data from unauthorized transfer",
            settings: {
              rules: { description: "DLP rules for detecting sensitive content" },
              actions: { description: "Actions on rule match", options: ["allow", "confirm", "block"] },
              transferMethods: { description: "Monitored transfer methods (email, web, USB, etc.)" }
            }
          },
          {
            type: "web-control",
            description: "Category-based web filtering and URL blocking",
            settings: {
              categories: { description: "Website categories with allow/warn/block actions" },
              safeSearch: { description: "Enforce safe search on search engines", options: ["on", "off"] },
              urlTagging: { description: "Log website categories for reporting", options: ["on", "off"] }
            }
          },
          {
            type: "tamper-protection",
            description: "Prevent users and malware from disabling Sophos protection",
            settings: {
              enabled: { description: "Enable tamper protection", recommended: true, options: ["on", "off"] },
              password: { description: "Tamper protection recovery password" }
            }
          },
          {
            type: "update-management",
            description: "Control when and how endpoint agents are updated",
            settings: {
              schedule: { description: "Update schedule (immediate, scheduled, manual)" },
              maintenanceWindow: { description: "Time window for updates" },
              channel: { description: "Update channel", options: ["recommended", "fixed"] }
            }
          },
          {
            type: "windows-firewall",
            description: "Manage Windows Firewall settings through Sophos Central",
            settings: {
              monitorConnections: { description: "Monitor and control network connections" },
              globalRules: { description: "Global firewall rules applied to all endpoints" }
            }
          }
        ],
        enforcementLevels: [
          { level: "recommended", description: "Use Sophos recommended settings (auto-updated)" },
          { level: "custom", description: "Admin-defined custom settings" },
          { level: "disabled", description: "Policy is disabled and not enforced" }
        ]
      };
      return {
        contents: [
          {
            uri: "sophos://policy-reference",
            mimeType: "application/json",
            text: JSON.stringify(policyReference, null, 2)
          }
        ]
      };
    }
  );
  server.resource(
    "mitre-mappings",
    "sophos://mitre-mappings",
    {
      description: "MITRE ATT&CK technique mappings for Sophos EDR/XDR detections \u2014 maps detection types to tactics and techniques",
      mimeType: "application/json"
    },
    async () => {
      const mitreMappings = {
        overview: "Sophos EDR/XDR detections are mapped to the MITRE ATT&CK framework. This resource lists common techniques detected by Sophos and their associated tactics.",
        detectionMappings: [
          {
            detectionType: "behavioralExecution",
            description: "Suspicious process behavior detected",
            techniques: [
              { id: "T1059", name: "Command and Scripting Interpreter", tactics: ["Execution"] },
              { id: "T1059.001", name: "PowerShell", tactics: ["Execution"] },
              { id: "T1059.003", name: "Windows Command Shell", tactics: ["Execution"] },
              { id: "T1204", name: "User Execution", tactics: ["Execution"] },
              { id: "T1204.002", name: "Malicious File", tactics: ["Execution"] }
            ]
          },
          {
            detectionType: "malwareExecution",
            description: "Known malware signature or behavior detected",
            techniques: [
              { id: "T1204.002", name: "Malicious File", tactics: ["Execution"] },
              { id: "T1566.001", name: "Spearphishing Attachment", tactics: ["Initial Access"] },
              { id: "T1027", name: "Obfuscated Files or Information", tactics: ["Defense Evasion"] },
              { id: "T1036", name: "Masquerading", tactics: ["Defense Evasion"] }
            ]
          },
          {
            detectionType: "exploitPrevention",
            description: "Exploit attempt blocked",
            techniques: [
              { id: "T1203", name: "Exploitation for Client Execution", tactics: ["Execution"] },
              { id: "T1068", name: "Exploitation for Privilege Escalation", tactics: ["Privilege Escalation"] },
              { id: "T1189", name: "Drive-by Compromise", tactics: ["Initial Access"] },
              { id: "T1211", name: "Exploitation for Defense Evasion", tactics: ["Defense Evasion"] }
            ]
          },
          {
            detectionType: "credential",
            description: "Credential theft or access attempt detected",
            techniques: [
              { id: "T1003", name: "OS Credential Dumping", tactics: ["Credential Access"] },
              { id: "T1003.001", name: "LSASS Memory", tactics: ["Credential Access"] },
              { id: "T1110", name: "Brute Force", tactics: ["Credential Access"] },
              { id: "T1555", name: "Credentials from Password Stores", tactics: ["Credential Access"] },
              { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactics: ["Credential Access"] }
            ]
          },
          {
            detectionType: "lateralMovement",
            description: "Lateral movement activity detected",
            techniques: [
              { id: "T1021", name: "Remote Services", tactics: ["Lateral Movement"] },
              { id: "T1021.001", name: "Remote Desktop Protocol", tactics: ["Lateral Movement"] },
              { id: "T1021.002", name: "SMB/Windows Admin Shares", tactics: ["Lateral Movement"] },
              { id: "T1021.003", name: "Distributed Component Object Model", tactics: ["Lateral Movement"] },
              { id: "T1021.006", name: "Windows Remote Management", tactics: ["Lateral Movement"] },
              { id: "T1570", name: "Lateral Tool Transfer", tactics: ["Lateral Movement"] }
            ]
          },
          {
            detectionType: "commandAndControl",
            description: "Command and control communication detected",
            techniques: [
              { id: "T1071", name: "Application Layer Protocol", tactics: ["Command and Control"] },
              { id: "T1071.001", name: "Web Protocols", tactics: ["Command and Control"] },
              { id: "T1071.004", name: "DNS", tactics: ["Command and Control"] },
              { id: "T1573", name: "Encrypted Channel", tactics: ["Command and Control"] },
              { id: "T1572", name: "Protocol Tunneling", tactics: ["Command and Control"] },
              { id: "T1105", name: "Ingress Tool Transfer", tactics: ["Command and Control"] }
            ]
          },
          {
            detectionType: "dataExfiltration",
            description: "Data exfiltration activity detected",
            techniques: [
              { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactics: ["Exfiltration"] },
              { id: "T1041", name: "Exfiltration Over C2 Channel", tactics: ["Exfiltration"] },
              { id: "T1567", name: "Exfiltration Over Web Service", tactics: ["Exfiltration"] },
              { id: "T1537", name: "Transfer Data to Cloud Account", tactics: ["Exfiltration"] }
            ]
          },
          {
            detectionType: "evasion",
            description: "Defense evasion technique detected",
            techniques: [
              { id: "T1055", name: "Process Injection", tactics: ["Defense Evasion", "Privilege Escalation"] },
              { id: "T1055.001", name: "Dynamic-link Library Injection", tactics: ["Defense Evasion"] },
              { id: "T1218", name: "System Binary Proxy Execution", tactics: ["Defense Evasion"] },
              { id: "T1562", name: "Impair Defenses", tactics: ["Defense Evasion"] },
              { id: "T1070", name: "Indicator Removal", tactics: ["Defense Evasion"] },
              { id: "T1112", name: "Modify Registry", tactics: ["Defense Evasion"] }
            ]
          },
          {
            detectionType: "pua",
            description: "Potentially Unwanted Application detected",
            techniques: [
              { id: "T1176", name: "Browser Extensions", tactics: ["Persistence"] },
              { id: "T1219", name: "Remote Access Software", tactics: ["Command and Control"] }
            ]
          },
          {
            detectionType: "webThreat",
            description: "Web-based threat detected and blocked",
            techniques: [
              { id: "T1189", name: "Drive-by Compromise", tactics: ["Initial Access"] },
              { id: "T1566.002", name: "Spearphishing Link", tactics: ["Initial Access"] },
              { id: "T1598", name: "Phishing for Information", tactics: ["Reconnaissance"] }
            ]
          }
        ],
        tactics: [
          "Reconnaissance",
          "Resource Development",
          "Initial Access",
          "Execution",
          "Persistence",
          "Privilege Escalation",
          "Defense Evasion",
          "Credential Access",
          "Discovery",
          "Lateral Movement",
          "Collection",
          "Command and Control",
          "Exfiltration",
          "Impact"
        ]
      };
      return {
        contents: [
          {
            uri: "sophos://mitre-mappings",
            mimeType: "application/json",
            text: JSON.stringify(mitreMappings, null, 2)
          }
        ]
      };
    }
  );
}

// src/prompts/index.ts
import { z as z8 } from "zod";
function registerPrompts(server) {
  server.prompt(
    "investigate-endpoint",
    "Guided workflow for investigating a suspicious endpoint in Sophos Central",
    {
      endpoint_id: z8.string().describe("The endpoint ID to investigate")
    },
    ({ endpoint_id }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: [
              `## Endpoint Investigation: ${endpoint_id}`,
              "",
              "Follow this structured investigation workflow:",
              "",
              "## Step 1: Endpoint Overview",
              `1. Get full endpoint details using **get_endpoint** with id \`${endpoint_id}\``,
              "2. Note: hostname, OS, health status, last seen time, tamper protection state",
              "3. Check agent version and installed Sophos products",
              "",
              "## Step 2: Alert Review",
              `4. List alerts for this endpoint using **list_alerts** filtered to the endpoint`,
              "5. For each alert, note severity, category, and timestamp",
              "6. Get full details on any HIGH/CRITICAL alerts using **get_alert**",
              "",
              "## Step 3: Detection Analysis",
              `7. Check EDR detections using **list_detections** for this endpoint`,
              "8. Review MITRE ATT&CK mappings for each detection",
              "9. Check if detections are part of a threat case using **get_threat_cases**",
              "",
              "## Step 4: Live Investigation",
              "10. If suspicious activity found, run targeted Live Discover queries:",
              "    - Running processes: `SELECT pid, name, path, cmdline FROM processes`",
              "    - Network connections: `SELECT pid, remote_address, remote_port FROM socket_events`",
              "    - Listening ports: `SELECT pid, port, address FROM listening_ports`",
              "",
              "## Step 5: Response Decision",
              "11. Based on findings, recommend one of:",
              "    - **No action**: False positive, document and close",
              "    - **Monitor**: Add to watchlist, increase logging",
              "    - **Isolate**: Network isolate via **isolate_endpoint** if active threat",
              "    - **Scan**: Trigger on-demand scan via **scan_endpoint**",
              "",
              "12. Document findings and actions taken"
            ].join("\n")
          }
        }
      ]
    })
  );
  server.prompt(
    "threat-hunt",
    "Hunt for indicators of compromise across endpoints using Sophos Live Discover",
    {
      indicator: z8.string().describe("IOC to hunt for (IP, domain, hash, filename, or process name)"),
      indicator_type: z8.string().optional().describe("Type of indicator: ip, domain, hash, filename, process (auto-detected if omitted)")
    },
    ({ indicator, indicator_type }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: [
              `## Threat Hunt: ${indicator}`,
              indicator_type ? `**Type:** ${indicator_type}` : "",
              "",
              "## Step 1: Determine IOC Type",
              `1. Identify the type of indicator: \`${indicator}\``,
              "   - IP address: looks like x.x.x.x",
              "   - Domain: contains dots, no port",
              "   - File hash: 32/40/64 hex chars (MD5/SHA1/SHA256)",
              "   - Filename: has extension",
              "   - Process: executable name",
              "",
              "## Step 2: Search Alerts & Detections",
              "2. Search alerts using **list_alerts** for references to this indicator",
              "3. Search detections using **list_detections** for matches",
              "",
              "## Step 3: Live Discover Queries",
              "4. Run appropriate Live Discover queries based on IOC type:",
              "",
              "**For IP addresses:**",
              "```sql",
              `SELECT pid, remote_address, remote_port, state FROM socket_events WHERE remote_address = '${indicator}';`,
              "```",
              "",
              "**For file hashes:**",
              "```sql",
              `SELECT path, sha256 FROM hash WHERE sha256 = '${indicator}';`,
              "```",
              "",
              "**For process names:**",
              "```sql",
              `SELECT pid, name, path, cmdline, start_time FROM processes WHERE name = '${indicator}';`,
              "```",
              "",
              "**For filenames:**",
              "```sql",
              `SELECT path, directory, filename, size, mtime FROM file WHERE filename = '${indicator}';`,
              "```",
              "",
              "## Step 4: Assess Scope",
              "5. Count affected endpoints",
              "6. Identify first and last seen timestamps",
              "7. Map lateral movement if multiple hosts affected",
              "",
              "## Step 5: Response",
              "8. For confirmed threats: isolate affected endpoints",
              "9. Document all findings with endpoint IDs and timestamps"
            ].join("\n")
          }
        }
      ]
    })
  );
  server.prompt(
    "incident-response",
    "Step-by-step incident response workflow: contain, investigate, remediate",
    {
      incident_description: z8.string().describe("Brief description of the incident")
    },
    ({ incident_description }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: [
              `## Incident Response: ${incident_description}`,
              "",
              "## Phase 1: Containment",
              "1. Identify affected endpoints from alerts using **list_alerts** with severity HIGH/CRITICAL",
              "2. For each confirmed compromised endpoint, isolate using **isolate_endpoint**",
              "3. Document isolation actions and timestamps",
              "",
              "## Phase 2: Investigation",
              "4. For each affected endpoint, run **get_endpoint** for full details",
              "5. Pull EDR detections using **list_detections** and review MITRE mappings",
              "6. Check threat cases using **get_threat_cases** for grouped analysis",
              "7. Search security events using **search_events** for the incident timeframe",
              "8. Run Live Discover queries for forensic data:",
              "   - Running processes and services",
              "   - Network connections and listening ports",
              "   - Scheduled tasks and startup items",
              "   - Recently modified files",
              "",
              "## Phase 3: Remediation",
              "9. Trigger on-demand scans via **scan_endpoint** on affected systems",
              "10. Review and update policies using **get_policy** / **get_policy_settings**",
              "11. Check for exclusions that may have allowed the threat using **list_exclusions**",
              "12. Resolve alerts using **resolve_alert** with action taken",
              "",
              "## Phase 4: Recovery",
              "13. Un-isolate cleaned endpoints using **unisolate_endpoint**",
              "14. Monitor for re-infection indicators",
              "15. Update detection rules and policies as needed",
              "",
              "## Phase 5: Lessons Learned",
              "16. Document timeline, root cause, and remediation steps",
              "17. Identify detection gaps and recommend improvements"
            ].join("\n")
          }
        }
      ]
    })
  );
  server.prompt(
    "health-audit",
    "Audit tenant and endpoint security health posture",
    {},
    () => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: [
              "## Security Health Audit",
              "",
              "## Step 1: Tenant Overview",
              "1. Get tenant health using **get_tenant_health**",
              "2. Review overall security score and risk areas",
              "",
              "## Step 2: Endpoint Health",
              "3. List all endpoints using **list_endpoints**",
              "4. Identify endpoints with:",
              "   - Bad health status (not 'good')",
              "   - Tamper protection disabled",
              "   - Outdated agent versions",
              "   - Not seen recently (>24 hours)",
              "",
              "## Step 3: Alert Review",
              "5. List unresolved alerts using **list_alerts** with status open",
              "6. Categorize by severity and age",
              "7. Flag any alerts older than 7 days",
              "",
              "## Step 4: Policy Review",
              "8. List all policies using **list_policies**",
              "9. Check for overly permissive settings",
              "10. Review exclusions using **list_exclusions** for unnecessary entries",
              "",
              "## Step 5: Report",
              "11. Summarize findings:",
              "    - Total endpoints and health distribution",
              "    - Open alert count by severity",
              "    - Policy compliance gaps",
              "    - Recommended actions (prioritized)"
            ].join("\n")
          }
        }
      ]
    })
  );
}

// src/index.ts
async function main() {
  const config = getConfig();
  const client = new SophosClient(config);
  const server = new McpServer({
    name: "sophos-mcp",
    version: "1.0.0",
    description: "MCP server for Sophos Central \u2014 endpoint management, EDR/XDR detections, alerts, Live Discover queries, and security policy management"
  });
  registerEndpointTools(server, client);
  registerAlertTools(server, client);
  registerDetectionTools(server, client);
  registerEventTools(server, client);
  registerPolicyTools(server, client);
  registerTenantTools(server, client);
  registerLiveDiscoverTools(server, client);
  registerResources(server);
  registerPrompts(server);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Sophos Central MCP server running on stdio");
}
main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
//# sourceMappingURL=index.js.map