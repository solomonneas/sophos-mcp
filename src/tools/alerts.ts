import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register alert management tools.
 *
 * Provides listing, retrieval, acknowledgment, resolution,
 * and available actions for Sophos Central alerts.
 */
export function registerAlertTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // list_alerts
  // -------------------------------------------------------------------------
  server.tool(
    "list_alerts",
    "List Sophos Central alerts with optional filters for severity, category, product, and date range",
    {
      severity: z
        .enum(["low", "medium", "high"])
        .optional()
        .describe("Filter by alert severity"),
      category: z
        .string()
        .optional()
        .describe(
          "Filter by alert category (e.g., malware, pua, runtimeDetections, policy, protection, general)"
        ),
      product: z
        .enum([
          "endpoint",
          "server",
          "mobile",
          "encryption",
          "emailGateway",
          "webGateway",
          "phishThreat",
          "wireless",
          "iaas",
          "firewall",
        ])
        .optional()
        .describe("Filter by Sophos product that generated the alert"),
      from: z
        .string()
        .optional()
        .describe("Return alerts raised after this ISO 8601 timestamp"),
      to: z
        .string()
        .optional()
        .describe("Return alerts raised before this ISO 8601 timestamp"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(25)
        .describe("Number of results to return (1-100)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
    },
    async ({ severity, category, product, from, to, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            managedAgent: alert.managedAgent
              ? {
                  id: alert.managedAgent.id,
                  type: alert.managedAgent.type,
                  name: alert.managedAgent.name,
                }
              : undefined,
            person: alert.person?.name,
            allowedActions: alert.allowedActions,
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
  // get_alert
  // -------------------------------------------------------------------------
  server.tool(
    "get_alert",
    "Get full details of a specific Sophos Central alert including description, managed agent info, and available response actions",
    {
      alert_id: z
        .string()
        .describe("Alert UUID"),
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
          data: alert.data,
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
  // acknowledge_alert
  // -------------------------------------------------------------------------
  server.tool(
    "acknowledge_alert",
    "Acknowledge a Sophos Central alert — marks it as reviewed without resolving it",
    {
      alert_id: z
        .string()
        .describe("Alert UUID to acknowledge"),
      message: z
        .string()
        .optional()
        .describe("Optional note or reason for acknowledgment"),
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
              type: "text" as const,
              text: JSON.stringify(
                {
                  ...result,
                  message: `Alert ${alert_id} acknowledged successfully.`,
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
  // resolve_alert
  // -------------------------------------------------------------------------
  server.tool(
    "resolve_alert",
    "Resolve and close a Sophos Central alert with a description of the action taken",
    {
      alert_id: z
        .string()
        .describe("Alert UUID to resolve"),
      action: z
        .enum(["cleanPua", "clean", "authPua", "clearThreat", "clearHmpa", "sendMsgPua", "sendMsgThreat"])
        .describe(
          "Resolution action: cleanPua (clean PUA), clean (clean threat), " +
          "authPua (authorize PUA), clearThreat (clear threat), clearHmpa (clear HMPA), " +
          "sendMsgPua (send message for PUA), sendMsgThreat (send message for threat)"
        ),
      message: z
        .string()
        .optional()
        .describe("Description of the remediation action taken"),
    },
    async ({ alert_id, action, message }) => {
      try {
        const result = await client.performAlertAction(alert_id, action, message);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  ...result,
                  message: `Alert ${alert_id} resolved with action '${action}'.`,
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
  // get_alert_actions
  // -------------------------------------------------------------------------
  server.tool(
    "get_alert_actions",
    "List available response actions for a specific Sophos Central alert — determines what actions can be performed",
    {
      alert_id: z
        .string()
        .describe("Alert UUID"),
    },
    async ({ alert_id }) => {
      try {
        const alert = await client.getAlert(alert_id);

        const actionDescriptions: Record<string, string> = {
          acknowledge: "Mark the alert as reviewed without taking action",
          cleanPua: "Clean the Potentially Unwanted Application",
          clean: "Clean/remove the detected threat",
          authPua: "Authorize the PUA (allow it to run)",
          clearThreat: "Clear the threat alert",
          clearHmpa: "Clear the HMPA (behavioral) detection alert",
          sendMsgPua: "Send a message to the endpoint about the PUA",
          sendMsgThreat: "Send a message to the endpoint about the threat",
          contactSupport: "Escalate to Sophos support",
        };

        const result = {
          alert_id,
          severity: alert.severity,
          category: alert.category,
          allowedActions: alert.allowedActions.map((action) => ({
            action,
            description: actionDescriptions[action] || `Perform '${action}' action`,
          })),
          actionCount: alert.allowedActions.length,
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
