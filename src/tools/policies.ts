import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register policy management tools.
 *
 * Provides listing, retrieval, settings inspection, and
 * exclusion management for Sophos Central policies.
 */
export function registerPolicyTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // list_policies
  // -------------------------------------------------------------------------
  server.tool(
    "list_policies",
    "List Sophos Central endpoint, server, and firewall policies with optional type filter",
    {
      type: z
        .enum([
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
          "update-management",
        ])
        .optional()
        .describe("Filter by policy type"),
      enabled: z
        .boolean()
        .optional()
        .describe("Filter by enabled/disabled state"),
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
    async ({ type, enabled, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
        };
        if (type) params.type = type;
        if (enabled !== undefined) params.enabled = enabled;

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
            lockedBy: pol.lockedBy,
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
  // get_policy
  // -------------------------------------------------------------------------
  server.tool(
    "get_policy",
    "Get full configuration details of a specific Sophos Central policy including all settings and scope",
    {
      policy_id: z
        .string()
        .describe("Policy UUID"),
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
          lockedBy: pol.lockedBy,
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
  // get_policy_settings
  // -------------------------------------------------------------------------
  server.tool(
    "get_policy_settings",
    "Get specific settings within a Sophos Central policy — extracts and formats individual configuration sections for easier analysis",
    {
      policy_id: z
        .string()
        .describe("Policy UUID"),
      setting_key: z
        .string()
        .optional()
        .describe(
          "Specific setting key to retrieve (e.g., 'malwareProtection', 'webControl', " +
          "'fileProtection'). If omitted, returns all settings."
        ),
    },
    async ({ policy_id, setting_key }) => {
      try {
        const pol = await client.getPolicy(policy_id);

        let settingsToReturn: Record<string, unknown>;

        if (setting_key) {
          const value = pol.settings[setting_key];
          if (value === undefined) {
            const availableKeys = Object.keys(pol.settings);
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(
                    {
                      error: `Setting '${setting_key}' not found in policy '${pol.name}'.`,
                      availableSettings: availableKeys,
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
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
          availableSettingKeys: Object.keys(pol.settings),
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
  // list_exclusions
  // -------------------------------------------------------------------------
  server.tool(
    "list_exclusions",
    "List global and policy-specific scanning exclusions in Sophos Central — important for security audits and troubleshooting false positives",
    {
      type: z
        .enum(["path", "process", "extension", "posixPath", "virtualPath", "amsi"])
        .optional()
        .describe("Filter by exclusion type"),
      search: z
        .string()
        .optional()
        .describe("Search exclusions by value or description"),
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
    async ({ type, search, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            comment: exc.comment,
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
}
