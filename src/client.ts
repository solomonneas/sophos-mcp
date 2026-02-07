import type { SophosConfig } from "./config.js";
import type {
  SophosPaginatedResponse,
  SophosTokenResponse,
  SophosWhoamiResponse,
  Endpoint,
  EndpointSoftware,
  Alert,
  Detection,
  ThreatCase,
  SecurityEvent,
  AuditLogEntry,
  Policy,
  ScanningExclusion,
  Tenant,
  TenantHealth,
  LiveDiscoverQueryRun,
  SavedLiveDiscoverQuery,
  LiveDiscoverResult,
} from "./types.js";

// ============================================================================
// Error Classes
// ============================================================================

/** Base error for all Sophos Central API errors */
export class SophosClientError extends Error {
  constructor(
    message: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = "SophosClientError";
  }
}

/** Authentication / authorization error */
export class SophosAuthError extends SophosClientError {
  constructor(message: string, statusCode?: number) {
    super(message, statusCode);
    this.name = "SophosAuthError";
  }
}

/** Rate limit error */
export class SophosRateLimitError extends SophosClientError {
  public retryAfter?: number;
  constructor(message: string, retryAfter?: number) {
    super(message, 429);
    this.name = "SophosRateLimitError";
    this.retryAfter = retryAfter;
  }
}

// ============================================================================
// Client
// ============================================================================

/**
 * HTTP client for the Sophos Central REST API.
 *
 * Handles OAuth2 authentication, tenant discovery, pagination, error mapping,
 * and timeout management. Uses the partner/organization/tenant API hierarchy
 * as documented in the Sophos Central API reference.
 */
export class SophosClient {
  private readonly config: SophosConfig;
  private accessToken?: string;
  private tokenExpiresAt?: number;
  private dataRegionUrl?: string;
  private tenantId?: string;

  constructor(config: SophosConfig) {
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
  private async authenticate(): Promise<string> {
    if (this.accessToken && this.tokenExpiresAt && Date.now() < this.tokenExpiresAt) {
      return this.accessToken;
    }

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: "token",
    });

    const { signal, clear } = this.createAbortSignal();
    let response: Response;
    try {
      response = await fetch(this.config.authUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
        signal,
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

    const tokenData = (await response.json()) as SophosTokenResponse;

    if (tokenData.errorCode) {
      throw new SophosAuthError(
        `OAuth2 error: ${tokenData.errorCode} — ${tokenData.message}`
      );
    }

    this.accessToken = tokenData.access_token;
    // Expire 60 seconds early to avoid edge cases
    this.tokenExpiresAt = Date.now() + (tokenData.expires_in - 60) * 1000;

    return this.accessToken;
  }

  /**
   * Discover the data region URL and tenant ID using the whoami endpoint.
   */
  private async discoverTenant(): Promise<void> {
    if (this.dataRegionUrl && this.tenantId) {
      return;
    }

    const token = await this.authenticate();
    const { signal, clear } = this.createAbortSignal();

    let response: Response;
    try {
      response = await fetch(`${this.config.globalUrl}/whoami/v1`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        signal,
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

    const whoami = (await response.json()) as SophosWhoamiResponse;
    this.dataRegionUrl = this.dataRegionUrl || whoami.apiHosts.dataRegion;
    this.tenantId = this.tenantId || whoami.id;
  }

  // --------------------------------------------------------------------------
  // Core HTTP
  // --------------------------------------------------------------------------

  private createAbortSignal(): { signal: AbortSignal; clear: () => void } {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
    return {
      signal: controller.signal,
      clear: () => clearTimeout(timeoutId),
    };
  }

  /**
   * Send an authenticated request to the Sophos Central API.
   */
  async request<T>(
    method: string,
    endpoint: string,
    params?: Record<string, string | number | boolean | undefined>,
    body?: unknown,
    useGlobalUrl = false
  ): Promise<T> {
    await this.discoverTenant();
    const token = await this.authenticate();
    const baseUrl = useGlobalUrl ? this.config.globalUrl : this.dataRegionUrl!;

    const url = new URL(`${baseUrl}${endpoint}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    // Add tenant header for data-region requests
    if (!useGlobalUrl && this.tenantId) {
      headers["X-Tenant-ID"] = this.tenantId;
    }

    const { signal, clear } = this.createAbortSignal();
    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal,
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
      return {} as T;
    }

    return (await response.json()) as T;
  }

  private async handleErrorResponse(response: Response): Promise<never> {
    let errorMsg = `${response.status} ${response.statusText}`;
    try {
      const errorBody = await response.json();
      if (errorBody.message) {
        errorMsg = `${errorMsg}: ${errorBody.message}`;
      } else if (errorBody.error) {
        errorMsg = `${errorMsg}: ${errorBody.error}`;
      }
    } catch {
      // ignore JSON parse errors on error responses
    }

    if (response.status === 401 || response.status === 403) {
      // Reset token on auth failure
      this.accessToken = undefined;
      this.tokenExpiresAt = undefined;
      throw new SophosAuthError(
        `Authentication failed: ${errorMsg}`,
        response.status
      );
    }

    if (response.status === 429) {
      const retryAfter = response.headers.get("Retry-After");
      throw new SophosRateLimitError(
        `Rate limited: ${errorMsg}`,
        retryAfter ? parseInt(retryAfter, 10) : undefined
      );
    }

    throw new SophosClientError(
      `Request failed: ${errorMsg}`,
      response.status
    );
  }

  async get<T>(
    endpoint: string,
    params?: Record<string, string | number | boolean | undefined>,
    useGlobalUrl = false
  ): Promise<T> {
    return this.request<T>("GET", endpoint, params, undefined, useGlobalUrl);
  }

  async post<T>(
    endpoint: string,
    body?: unknown,
    params?: Record<string, string | number | boolean | undefined>,
    useGlobalUrl = false
  ): Promise<T> {
    return this.request<T>("POST", endpoint, params, body, useGlobalUrl);
  }

  async patch<T>(
    endpoint: string,
    body?: unknown,
    params?: Record<string, string | number | boolean | undefined>
  ): Promise<T> {
    return this.request<T>("PATCH", endpoint, params, body);
  }

  async delete<T>(
    endpoint: string,
    params?: Record<string, string | number | boolean | undefined>
  ): Promise<T> {
    return this.request<T>("DELETE", endpoint, params);
  }

  // --------------------------------------------------------------------------
  // Endpoint Methods
  // --------------------------------------------------------------------------

  /** List endpoints with optional filters */
  async getEndpoints(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<Endpoint>> {
    return this.get("/endpoint/v1/endpoints", params);
  }

  /** Get a single endpoint by ID */
  async getEndpoint(endpointId: string): Promise<Endpoint> {
    return this.get(`/endpoint/v1/endpoints/${endpointId}`);
  }

  /** Isolate an endpoint */
  async isolateEndpoint(
    endpointId: string,
    comment?: string
  ): Promise<{ id: string; status: string }> {
    return this.post(`/endpoint/v1/endpoints/${endpointId}/isolation`, {
      enabled: true,
      comment,
    });
  }

  /** Remove isolation from an endpoint */
  async unisolateEndpoint(
    endpointId: string,
    comment?: string
  ): Promise<{ id: string; status: string }> {
    return this.post(`/endpoint/v1/endpoints/${endpointId}/isolation`, {
      enabled: false,
      comment,
    });
  }

  /** Trigger an on-demand scan on an endpoint */
  async scanEndpoint(endpointId: string): Promise<{ id: string; status: string }> {
    return this.post(`/endpoint/v1/endpoints/${endpointId}/scans`, {
      type: "full",
    });
  }

  /** Get installed software on an endpoint */
  async getEndpointSoftware(
    endpointId: string,
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<EndpointSoftware>> {
    return this.get(`/endpoint/v1/endpoints/${endpointId}/software`, params);
  }

  // --------------------------------------------------------------------------
  // Alert Methods
  // --------------------------------------------------------------------------

  /** List alerts with optional filters */
  async getAlerts(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<Alert>> {
    return this.get("/common/v1/alerts", params);
  }

  /** Get a single alert by ID */
  async getAlert(alertId: string): Promise<Alert> {
    return this.get(`/common/v1/alerts/${alertId}`);
  }

  /** Perform an action on an alert (acknowledge, cleanPua, etc.) */
  async performAlertAction(
    alertId: string,
    action: string,
    message?: string
  ): Promise<{ id: string; action: string; completedAt: string }> {
    return this.post(`/common/v1/alerts/${alertId}/actions`, {
      action,
      message,
    });
  }

  // --------------------------------------------------------------------------
  // Detection Methods
  // --------------------------------------------------------------------------

  /** List EDR/XDR detections */
  async getDetections(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<Detection>> {
    return this.get("/xdr/v1/detections", params);
  }

  /** Get a single detection by ID */
  async getDetection(detectionId: string): Promise<Detection> {
    return this.get(`/xdr/v1/detections/${detectionId}`);
  }

  /** List threat cases */
  async getThreatCases(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<ThreatCase>> {
    return this.get("/xdr/v1/threat-cases", params);
  }

  /** Get detections for a specific threat case */
  async getCaseDetections(
    caseId: string,
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<Detection>> {
    return this.get(`/xdr/v1/threat-cases/${caseId}/detections`, params);
  }

  /** Update threat case status */
  async updateCaseStatus(
    caseId: string,
    status: string,
    assigneeId?: string
  ): Promise<ThreatCase> {
    const body: Record<string, unknown> = { status };
    if (assigneeId) body.assignee = { id: assigneeId };
    return this.patch(`/xdr/v1/threat-cases/${caseId}`, body);
  }

  // --------------------------------------------------------------------------
  // Event Methods
  // --------------------------------------------------------------------------

  /** Search security events */
  async getEvents(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<SecurityEvent>> {
    return this.get("/siem/v1/events", params);
  }

  /** Get a single event by ID */
  async getEvent(eventId: string): Promise<SecurityEvent> {
    return this.get(`/siem/v1/events/${eventId}`);
  }

  /** Get audit logs */
  async getAuditLogs(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<AuditLogEntry>> {
    return this.get("/siem/v1/audit/events", params);
  }

  // --------------------------------------------------------------------------
  // Policy Methods
  // --------------------------------------------------------------------------

  /** List policies */
  async getPolicies(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<Policy>> {
    return this.get("/endpoint/v1/policies", params);
  }

  /** Get a single policy by ID */
  async getPolicy(policyId: string): Promise<Policy> {
    return this.get(`/endpoint/v1/policies/${policyId}`);
  }

  /** List scanning exclusions */
  async getExclusions(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<ScanningExclusion>> {
    return this.get("/endpoint/v1/settings/exclusions/scanning", params);
  }

  // --------------------------------------------------------------------------
  // Tenant Methods
  // --------------------------------------------------------------------------

  /** List managed tenants (partner/organization view) */
  async getTenants(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<Tenant>> {
    return this.get("/partner/v1/tenants", params, true);
  }

  /** Get a single tenant by ID */
  async getTenant(tenantId: string): Promise<Tenant> {
    return this.get(`/partner/v1/tenants/${tenantId}`, undefined, true);
  }

  // --------------------------------------------------------------------------
  // Live Discover Methods
  // --------------------------------------------------------------------------

  /** Execute a Live Discover query */
  async runLiveDiscoverQuery(
    sql: string,
    endpointIds: string[],
    variables?: Record<string, string>
  ): Promise<LiveDiscoverQueryRun> {
    return this.post("/live-discover/v1/queries/runs", {
      sql,
      matchEndpoints: endpointIds.map((id) => ({ id })),
      variables: variables
        ? Object.entries(variables).map(([name, value]) => ({ name, value }))
        : undefined,
    });
  }

  /** List saved Live Discover queries */
  async getSavedQueries(
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<SophosPaginatedResponse<SavedLiveDiscoverQuery>> {
    return this.get("/live-discover/v1/queries", params);
  }

  /** Get results for a Live Discover query run */
  async getQueryResults(
    queryRunId: string,
    params: Record<string, string | number | boolean | undefined> = {}
  ): Promise<{ items: LiveDiscoverResult[]; status: string }> {
    return this.get(`/live-discover/v1/queries/runs/${queryRunId}/results`, params);
  }
}
