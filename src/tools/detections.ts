import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register EDR/XDR detection tools.
 *
 * Provides listing, retrieval, threat case management,
 * and MITRE ATT&CK mapping for Sophos Central detections.
 */
export function registerDetectionTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // list_detections
  // -------------------------------------------------------------------------
  server.tool(
    "list_detections",
    "List Sophos EDR/XDR detections with optional filters for severity, type, endpoint, and date range",
    {
      severity: z
        .enum(["critical", "high", "medium", "low", "info"])
        .optional()
        .describe("Filter by detection severity"),
      type: z
        .string()
        .optional()
        .describe(
          "Filter by detection type (e.g., malwareExecution, behavioralExecution, " +
          "exploitPrevention, lateralMovement, commandAndControl, credential, evasion)"
        ),
      endpointId: z
        .string()
        .optional()
        .describe("Filter detections for a specific endpoint ID"),
      from: z
        .string()
        .optional()
        .describe("Return detections after this ISO 8601 timestamp"),
      to: z
        .string()
        .optional()
        .describe("Return detections before this ISO 8601 timestamp"),
      mitreTechnique: z
        .string()
        .optional()
        .describe("Filter by MITRE ATT&CK technique ID (e.g., T1059.001)"),
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
    async ({
      severity,
      type,
      endpointId,
      from,
      to,
      mitreTechnique,
      pageSize,
      page,
    }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
              os: det.endpoint.os,
            },
            process: det.process
              ? {
                  name: det.process.name,
                  path: det.process.path,
                  sha256: det.process.sha256,
                }
              : undefined,
            user: det.user?.name,
            mitreTechniques: det.mitreTechniques.map((t) => ({
              id: t.id,
              name: t.name,
              tactics: t.tactics,
            })),
            indicatorCount: det.indicators.length,
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
  // get_detection
  // -------------------------------------------------------------------------
  server.tool(
    "get_detection",
    "Get full details of a Sophos EDR/XDR detection including process tree, MITRE ATT&CK mapping, indicators, and raw event data",
    {
      detection_id: z
        .string()
        .describe("Detection UUID"),
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
          process: det.process
            ? {
                pid: det.process.pid,
                name: det.process.name,
                path: det.process.path,
                commandLine: det.process.commandLine,
                sha256: det.process.sha256,
                parentPid: det.process.parentPid,
                parentName: det.process.parentName,
              }
            : undefined,
          user: det.user,
          mitreTechniques: det.mitreTechniques.map((t) => ({
            id: t.id,
            name: t.name,
            tactics: t.tactics,
            url: t.url,
          })),
          indicators: det.indicators.map((ind) => ({
            type: ind.type,
            value: ind.value,
            description: ind.description,
          })),
          rawData: det.rawData,
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
  // get_threat_cases
  // -------------------------------------------------------------------------
  server.tool(
    "get_threat_cases",
    "List Sophos threat cases — groups of related EDR/XDR detections that form a single incident narrative",
    {
      status: z
        .enum(["new", "investigating", "inProgress", "containment", "resolved", "closed"])
        .optional()
        .describe("Filter by threat case status"),
      severity: z
        .enum(["critical", "high", "medium", "low", "info"])
        .optional()
        .describe("Filter by severity"),
      from: z
        .string()
        .optional()
        .describe("Return cases created after this ISO 8601 timestamp"),
      to: z
        .string()
        .optional()
        .describe("Return cases created before this ISO 8601 timestamp"),
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
    async ({ status, severity, from, to, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            mitreTechniques: tc.mitreTechniques.map((t) => `${t.id} (${t.name})`),
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
  // get_case_detections
  // -------------------------------------------------------------------------
  server.tool(
    "get_case_detections",
    "Get all detections within a Sophos threat case — shows every detection that contributed to the case",
    {
      case_id: z
        .string()
        .describe("Threat case UUID"),
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
    async ({ case_id, pageSize, page }) => {
      try {
        const response = await client.getCaseDetections(case_id, {
          pageSize,
          page,
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
              id: det.endpoint.id,
            },
            process: det.process
              ? {
                  name: det.process.name,
                  path: det.process.path,
                  commandLine: det.process.commandLine,
                }
              : undefined,
            user: det.user?.name,
            mitreTechniques: det.mitreTechniques.map((t) => t.id),
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

  // -------------------------------------------------------------------------
  // update_case_status
  // -------------------------------------------------------------------------
  server.tool(
    "update_case_status",
    "Update the status of a Sophos threat case and optionally assign it to an analyst",
    {
      case_id: z
        .string()
        .describe("Threat case UUID"),
      status: z
        .enum(["new", "investigating", "inProgress", "containment", "resolved", "closed"])
        .describe("New status for the threat case"),
      assignee_id: z
        .string()
        .optional()
        .describe("User ID to assign the case to"),
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
          message: `Threat case ${case_id} updated to status '${status}'.`,
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
