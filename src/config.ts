/**
 * Configuration for the Sophos Central MCP server.
 *
 * Sophos Central uses OAuth2 client credentials for authentication.
 * You need a service principal (client ID + client secret) created in
 * Sophos Central Admin > Global Settings > API Credentials Management.
 *
 * Required environment variables:
 *   - SOPHOS_CLIENT_ID:     OAuth2 client ID from Sophos Central
 *   - SOPHOS_CLIENT_SECRET: OAuth2 client secret from Sophos Central
 *
 * Optional:
 *   - SOPHOS_TENANT_ID: Specific tenant ID (required for partner/organization accounts)
 *   - SOPHOS_API_URL:   Override the base API URL (default: auto-discovered via whoami)
 *   - SOPHOS_AUTH_URL:  Override the OAuth2 token endpoint
 *   - SOPHOS_TIMEOUT:   Request timeout in seconds (default: 30)
 */

export interface SophosConfig {
  /** OAuth2 client ID */
  clientId: string;
  /** OAuth2 client secret */
  clientSecret: string;
  /** Specific tenant ID (for partner/org accounts) */
  tenantId?: string;
  /** Override data region API URL */
  apiUrl?: string;
  /** OAuth2 token endpoint */
  authUrl: string;
  /** Global API base URL (for whoami, partner endpoints) */
  globalUrl: string;
  /** Request timeout in milliseconds */
  timeout: number;
}

/** Default Sophos Central API endpoints */
const SOPHOS_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token";
const SOPHOS_GLOBAL_URL = "https://api.central.sophos.com";

/**
 * Load and validate configuration from environment variables.
 * @throws {Error} if required variables are missing
 */
export function getConfig(): SophosConfig {
  const clientId = process.env.SOPHOS_CLIENT_ID;
  if (!clientId) {
    throw new Error(
      "SOPHOS_CLIENT_ID environment variable is required. " +
        "Create API credentials in Sophos Central > Global Settings > API Credentials Management."
    );
  }

  const clientSecret = process.env.SOPHOS_CLIENT_SECRET;
  if (!clientSecret) {
    throw new Error(
      "SOPHOS_CLIENT_SECRET environment variable is required. " +
        "Create API credentials in Sophos Central > Global Settings > API Credentials Management."
    );
  }

  const tenantId = process.env.SOPHOS_TENANT_ID;
  const apiUrl = process.env.SOPHOS_API_URL?.replace(/\/+$/, "");
  const authUrl = (process.env.SOPHOS_AUTH_URL || SOPHOS_AUTH_URL).replace(/\/+$/, "");
  const globalUrl = SOPHOS_GLOBAL_URL;
  const timeout = parseInt(process.env.SOPHOS_TIMEOUT ?? "30", 10) * 1000;

  return {
    clientId,
    clientSecret,
    tenantId,
    apiUrl,
    authUrl,
    globalUrl,
    timeout,
  };
}
