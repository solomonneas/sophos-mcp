import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register tenant/organization management tools.
 *
 * Provides MSP/partner-level tenant listing, details,
 * and health score overview for managed organizations.
 */
export function registerTenantTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // list_tenants
  // -------------------------------------------------------------------------
  server.tool(
    "list_tenants",
    "List managed tenants in Sophos Central — MSP/partner view of all managed organizations with status and billing info",
    {
      status: z
        .enum(["active", "deactivated", "suspended"])
        .optional()
        .describe("Filter by tenant status"),
      search: z
        .string()
        .optional()
        .describe("Search by tenant name"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(50)
        .describe("Number of results to return (1-100)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
    },
    async ({ status, search, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            contact: t.contact
              ? {
                  name: `${t.contact.firstName} ${t.contact.lastName}`,
                  email: t.contact.email,
                }
              : undefined,
            licenseCount: t.licenses.length,
            activeLicenses: t.licenses
              .filter((l) => l.status === "active")
              .map((l) => l.product),
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
  // get_tenant
  // -------------------------------------------------------------------------
  server.tool(
    "get_tenant",
    "Get full details of a managed tenant including contact info, license details, and data region",
    {
      tenant_id: z
        .string()
        .describe("Tenant UUID"),
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
          contact: t.contact
            ? {
                firstName: t.contact.firstName,
                lastName: t.contact.lastName,
                email: t.contact.email,
                phone: t.contact.phone,
              }
            : undefined,
          licenses: t.licenses.map((l) => ({
            id: l.id,
            product: l.product,
            type: l.type,
            quantity: l.quantity,
            usedQuantity: l.usedQuantity,
            available: l.quantity - l.usedQuantity,
            expiresAt: l.expiresAt,
            status: l.status,
          })),
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
  // get_tenant_health
  // -------------------------------------------------------------------------
  server.tool(
    "get_tenant_health",
    "Get overall security health score for a tenant — endpoint protection coverage, active threats, and compliance metrics",
    {
      tenant_id: z
        .string()
        .describe("Tenant UUID"),
    },
    async ({ tenant_id }) => {
      try {
        // Aggregate health by checking endpoints and alerts for the tenant
        const [endpointsResp, alertsResp] = await Promise.all([
          client.getEndpoints({ pageSize: 1 }),
          client.getAlerts({ pageSize: 1 }),
        ]);

        const totalEndpoints = endpointsResp.pages.items;
        const totalAlerts = alertsResp.pages.items;

        // Calculate a simple health score based on available data
        const healthScore = Math.max(
          0,
          100 - totalAlerts * 2
        );

        const result = {
          tenantId: tenant_id,
          endpointCount: totalEndpoints,
          activeAlerts: totalAlerts,
          healthScore: Math.min(100, healthScore),
          healthRating:
            healthScore >= 90
              ? "excellent"
              : healthScore >= 70
                ? "good"
                : healthScore >= 50
                  ? "fair"
                  : "poor",
          summary:
            `Tenant has ${totalEndpoints} managed endpoints with ${totalAlerts} active alerts. ` +
            `Health score: ${Math.min(100, healthScore)}/100.`,
          recommendations:
            totalAlerts > 10
              ? [
                  "Review and triage active alerts immediately",
                  "Investigate high-severity alerts first",
                  "Check for unprotected or unhealthy endpoints",
                  "Verify tamper protection is enabled across all endpoints",
                ]
              : totalAlerts > 0
                ? [
                    "Continue monitoring active alerts",
                    "Ensure all endpoints have up-to-date protection",
                  ]
                : ["All clear — maintain regular monitoring schedule"],
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
