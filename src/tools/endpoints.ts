import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register endpoint management tools.
 *
 * Provides listing, detailed retrieval, isolation, scanning,
 * and software inventory for Sophos Central managed endpoints.
 */
export function registerEndpointTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // list_endpoints
  // -------------------------------------------------------------------------
  server.tool(
    "list_endpoints",
    "List Sophos Central managed endpoints with optional filters for hostname, health status, OS platform, type, group, tamper protection, and isolation state",
    {
      search: z
        .string()
        .optional()
        .describe("Search by hostname, IP address, or associated person name"),
      healthStatus: z
        .enum(["good", "suspicious", "bad", "unknown"])
        .optional()
        .describe("Filter by overall health status"),
      type: z
        .enum(["computer", "server", "securityVm"])
        .optional()
        .describe("Filter by endpoint type"),
      os_platform: z
        .enum(["windows", "linux", "macOS"])
        .optional()
        .describe("Filter by operating system platform"),
      tamperProtectionEnabled: z
        .boolean()
        .optional()
        .describe("Filter by tamper protection status"),
      isolationStatus: z
        .enum(["isolated", "notIsolated"])
        .optional()
        .describe("Filter by network isolation status"),
      groupId: z
        .string()
        .optional()
        .describe("Filter by endpoint group ID"),
      lastSeenBefore: z
        .string()
        .optional()
        .describe("Filter endpoints last seen before this ISO 8601 timestamp"),
      lastSeenAfter: z
        .string()
        .optional()
        .describe("Filter endpoints last seen after this ISO 8601 timestamp"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(50)
        .describe("Number of results to return (1-500)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
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
      page,
    }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
        };
        if (search) params.search = search;
        if (healthStatus) params.healthStatus = healthStatus;
        if (type) params.type = type;
        if (os_platform) params["os.platform"] = os_platform;
        if (tamperProtectionEnabled !== undefined) {
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
            associatedPerson: ep.associatedPerson?.name,
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
          pageSize,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // get_endpoint
  // -------------------------------------------------------------------------
  server.tool(
    "get_endpoint",
    "Get full details of a specific Sophos Central endpoint including health status, assigned products, tamper protection, isolation state, and associated person",
    {
      endpoint_id: z
        .string()
        .describe("Endpoint UUID"),
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
            serviceDetails: ep.health.services.serviceDetails,
          },
          os: {
            platform: ep.os.platform,
            name: ep.os.name,
            majorVersion: ep.os.majorVersion,
            minorVersion: ep.os.minorVersion,
            build: ep.os.build,
            isServer: ep.os.isServer,
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
            version: p.version,
          })),
          tenantId: ep.tenant.id,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // isolate_endpoint
  // -------------------------------------------------------------------------
  server.tool(
    "isolate_endpoint",
    "Network isolate a Sophos Central endpoint for incident response — the endpoint can only communicate with Sophos Central",
    {
      endpoint_id: z
        .string()
        .describe("Endpoint UUID to isolate"),
      comment: z
        .string()
        .optional()
        .describe("Reason for isolating the endpoint"),
    },
    async ({ endpoint_id, comment }) => {
      try {
        const result = await client.isolateEndpoint(endpoint_id, comment);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  ...result,
                  message: `Endpoint ${endpoint_id} has been network isolated. It can only communicate with Sophos Central.`,
                  warning:
                    "The endpoint is now disconnected from the network. Use unisolate_endpoint to restore connectivity.",
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // unisolate_endpoint
  // -------------------------------------------------------------------------
  server.tool(
    "unisolate_endpoint",
    "Remove network isolation from a Sophos Central endpoint, restoring normal network connectivity",
    {
      endpoint_id: z
        .string()
        .describe("Endpoint UUID to unisolate"),
      comment: z
        .string()
        .optional()
        .describe("Reason for removing isolation"),
    },
    async ({ endpoint_id, comment }) => {
      try {
        const result = await client.unisolateEndpoint(endpoint_id, comment);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  ...result,
                  message: `Network isolation removed from endpoint ${endpoint_id}. Normal connectivity restored.`,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // scan_endpoint
  // -------------------------------------------------------------------------
  server.tool(
    "scan_endpoint",
    "Trigger a full on-demand antivirus scan on a Sophos Central endpoint",
    {
      endpoint_id: z
        .string()
        .describe("Endpoint UUID to scan"),
    },
    async ({ endpoint_id }) => {
      try {
        const result = await client.scanEndpoint(endpoint_id);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  ...result,
                  message: `Full scan initiated on endpoint ${endpoint_id}. Check endpoint events for scan results.`,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );

  // -------------------------------------------------------------------------
  // get_endpoint_software
  // -------------------------------------------------------------------------
  server.tool(
    "get_endpoint_software",
    "List installed software on a Sophos Central endpoint — useful for vulnerability assessment and software inventory",
    {
      endpoint_id: z
        .string()
        .describe("Endpoint UUID"),
      search: z
        .string()
        .optional()
        .describe("Search by software name or publisher"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(200)
        .default(100)
        .describe("Number of results to return (1-200)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
    },
    async ({ endpoint_id, search, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            size: sw.size,
          })),
          total: response.pages.items,
          page: response.pages.current,
          totalPages: response.pages.total,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );
}
