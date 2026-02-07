import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register security event and audit log tools.
 *
 * Provides search, retrieval, type listing, and audit trail
 * for Sophos Central SIEM events.
 */
export function registerEventTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // search_events
  // -------------------------------------------------------------------------
  server.tool(
    "search_events",
    "Search Sophos Central security events by type, severity, endpoint, source, and date range — the primary SIEM event feed",
    {
      type: z
        .string()
        .optional()
        .describe(
          "Filter by event type (e.g., Event::Endpoint::Threat::Detected, " +
          "Event::Endpoint::WebFilteringBlocked, Event::Endpoint::Threat::CleanedUp, " +
          "Event::Firewall::Blocked)"
        ),
      severity: z
        .enum(["none", "low", "medium", "high", "critical"])
        .optional()
        .describe("Filter by event severity"),
      endpointId: z
        .string()
        .optional()
        .describe("Filter events for a specific endpoint ID"),
      sourceType: z
        .string()
        .optional()
        .describe("Filter by event source (e.g., antivirus, deviceControl, firewall)"),
      from: z
        .string()
        .optional()
        .describe("Return events after this ISO 8601 timestamp"),
      to: z
        .string()
        .optional()
        .describe("Return events before this ISO 8601 timestamp"),
      search: z
        .string()
        .optional()
        .describe("Full-text search across event name and location"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(200)
        .default(50)
        .describe("Number of results to return (1-200)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
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
      page,
    }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            endpoint: evt.endpoint
              ? {
                  id: evt.endpoint.id,
                  hostname: evt.endpoint.hostname,
                  type: evt.endpoint.type,
                }
              : undefined,
            user: evt.user?.name,
            ioc: evt.ioc,
            iocType: evt.iocType,
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
  // get_event
  // -------------------------------------------------------------------------
  server.tool(
    "get_event",
    "Get full details of a specific Sophos Central security event including customer data, IOCs, and endpoint context",
    {
      event_id: z
        .string()
        .describe("Event UUID"),
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
          iocType: evt.iocType,
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
  // list_event_types
  // -------------------------------------------------------------------------
  server.tool(
    "list_event_types",
    "List available Sophos Central security event types and their descriptions — useful for building event search queries",
    {},
    async () => {
      try {
        const eventTypes = [
          {
            type: "Event::Endpoint::Threat::Detected",
            description: "Malware or threat detected on an endpoint",
            severity: "high",
            source: "antivirus",
          },
          {
            type: "Event::Endpoint::Threat::CleanedUp",
            description: "Detected threat was successfully cleaned/removed",
            severity: "low",
            source: "antivirus",
          },
          {
            type: "Event::Endpoint::Threat::NotBlocked",
            description: "Threat detected but could not be blocked automatically",
            severity: "critical",
            source: "antivirus",
          },
          {
            type: "Event::Endpoint::Threat::PuaDetected",
            description: "Potentially Unwanted Application detected",
            severity: "medium",
            source: "antivirus",
          },
          {
            type: "Event::Endpoint::Threat::PuaCleanedUp",
            description: "PUA was successfully cleaned/removed",
            severity: "low",
            source: "antivirus",
          },
          {
            type: "Event::Endpoint::Application::Blocked",
            description: "Application blocked by application control policy",
            severity: "medium",
            source: "applicationControl",
          },
          {
            type: "Event::Endpoint::DataLossPrevention",
            description: "Data loss prevention rule triggered",
            severity: "high",
            source: "dlp",
          },
          {
            type: "Event::Endpoint::WebControlViolation",
            description: "Web control policy violation (category-based blocking)",
            severity: "medium",
            source: "webControl",
          },
          {
            type: "Event::Endpoint::WebFilteringBlocked",
            description: "Malicious or phishing website blocked",
            severity: "high",
            source: "webFiltering",
          },
          {
            type: "Event::Endpoint::UpdateSuccess",
            description: "Endpoint agent updated successfully",
            severity: "none",
            source: "updating",
          },
          {
            type: "Event::Endpoint::UpdateFailure",
            description: "Endpoint agent update failed",
            severity: "medium",
            source: "updating",
          },
          {
            type: "Event::Endpoint::SavScanComplete",
            description: "Scheduled or on-demand scan completed",
            severity: "none",
            source: "antivirus",
          },
          {
            type: "Event::Endpoint::CoreRestore::Failed",
            description: "Endpoint core component restore failed",
            severity: "high",
            source: "core",
          },
          {
            type: "Event::Firewall::Allowed",
            description: "Network traffic allowed by firewall policy",
            severity: "none",
            source: "firewall",
          },
          {
            type: "Event::Firewall::Blocked",
            description: "Network traffic blocked by firewall policy",
            severity: "medium",
            source: "firewall",
          },
          {
            type: "Event::Mobile::ComplianceViolation",
            description: "Mobile device compliance policy violation",
            severity: "medium",
            source: "mobile",
          },
        ];

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { eventTypes, total: eventTypes.length },
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
  // get_audit_logs
  // -------------------------------------------------------------------------
  server.tool(
    "get_audit_logs",
    "Get the admin audit trail from Sophos Central — tracks all administrative actions including policy changes, user management, and configuration updates",
    {
      actorType: z
        .enum(["user", "system", "api"])
        .optional()
        .describe("Filter by actor type"),
      from: z
        .string()
        .optional()
        .describe("Return audit events after this ISO 8601 timestamp"),
      to: z
        .string()
        .optional()
        .describe("Return audit events before this ISO 8601 timestamp"),
      search: z
        .string()
        .optional()
        .describe("Search by actor name, description, or target name"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(200)
        .default(50)
        .describe("Number of results to return (1-200)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
    },
    async ({ actorType, from, to, search, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
              type: log.actor.type,
            },
            target: log.target
              ? {
                  name: log.target.name,
                  type: log.target.type,
                }
              : undefined,
            result: log.result,
            sourceIp: log.sourceIp,
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
