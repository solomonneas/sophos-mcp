import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SophosClient } from "../client.js";

/**
 * Register Live Discover tools.
 *
 * Live Discover is Sophos's osquery-based live endpoint querying capability,
 * allowing SQL queries to run directly on managed endpoints for real-time
 * investigation and threat hunting.
 */
export function registerLiveDiscoverTools(
  server: McpServer,
  client: SophosClient
): void {
  // -------------------------------------------------------------------------
  // run_query
  // -------------------------------------------------------------------------
  server.tool(
    "run_query",
    "Execute a Live Discover SQL query (osquery) on one or more Sophos Central endpoints — for real-time investigation and threat hunting",
    {
      sql: z
        .string()
        .describe(
          "SQL query to execute on endpoints (osquery syntax). " +
          "Example: SELECT pid, name, path FROM processes WHERE name LIKE '%suspicious%'"
        ),
      endpoint_ids: z
        .array(z.string())
        .min(1)
        .max(50)
        .describe("Array of endpoint UUIDs to run the query on (1-50 endpoints)"),
      variables: z
        .record(z.string())
        .optional()
        .describe("Query variables as key-value pairs for parameterized queries"),
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
            status: ep.status,
          })),
          createdAt: queryRun.createdAt,
          message:
            queryRun.status === "finished"
              ? `Query completed. Use get_query_results with queryRunId '${queryRun.id}' to retrieve results.`
              : `Query submitted (status: ${queryRun.status}). Poll get_query_results with queryRunId '${queryRun.id}' for results.`,
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
  // list_saved_queries
  // -------------------------------------------------------------------------
  server.tool(
    "list_saved_queries",
    "List saved Live Discover queries in Sophos Central — includes built-in and custom queries with their SQL and supported platforms",
    {
      category: z
        .enum([
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
          "custom",
        ])
        .optional()
        .describe("Filter by query category"),
      search: z
        .string()
        .optional()
        .describe("Search by query name or description"),
      builtIn: z
        .boolean()
        .optional()
        .describe("Filter by built-in (true) or custom (false) queries"),
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
    async ({ category, search, builtIn, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
        };
        if (category) params.category = category;
        if (search) params.search = search;
        if (builtIn !== undefined) params.builtIn = builtIn;

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
            createdAt: q.createdAt,
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
  // get_query_results
  // -------------------------------------------------------------------------
  server.tool(
    "get_query_results",
    "Retrieve results from a completed Live Discover query run — returns tabular data from each endpoint",
    {
      query_run_id: z
        .string()
        .describe("Query run UUID returned by run_query"),
      endpoint_id: z
        .string()
        .optional()
        .describe("Filter results for a specific endpoint ID"),
      pageSize: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(100)
        .describe("Number of result rows to return (1-500)"),
      page: z
        .number()
        .int()
        .min(1)
        .default(1)
        .describe("Page number"),
    },
    async ({ query_run_id, endpoint_id, pageSize, page }) => {
      try {
        const params: Record<string, string | number | boolean | undefined> = {
          pageSize,
          page,
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
            rows: r.rows,
          })),
          endpointCount: response.items.length,
          totalRows: response.items.reduce((sum, r) => sum + r.rows.length, 0),
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
  // list_query_categories
  // -------------------------------------------------------------------------
  server.tool(
    "list_query_categories",
    "List available Live Discover query categories with descriptions and example queries — helps discover what you can query",
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
              "SELECT p.pid, p.name, p.path, p.cmdline, pp.name AS parent_name FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid",
            ],
          },
          {
            category: "network",
            description: "Network connections, listening ports, DNS cache, ARP table",
            exampleQueries: [
              "SELECT pid, remote_address, remote_port, local_port, state, protocol FROM process_open_sockets WHERE remote_address != '' AND remote_address != '127.0.0.1'",
              "SELECT pid, port, address, protocol FROM listening_ports WHERE port NOT IN (80, 443, 22)",
              "SELECT pid, remote_address, remote_port, state FROM socket_events WHERE remote_port = 4444",
            ],
          },
          {
            category: "filesystem",
            description: "File metadata, hashes, recently modified files, downloads",
            exampleQueries: [
              "SELECT path, filename, size, mtime, sha256 FROM hash WHERE path = '$$filePath$$'",
              "SELECT path, filename, size, mtime FROM file WHERE directory = '$$directory$$'",
              "SELECT path, sha256 FROM hash WHERE path LIKE '/tmp/%' AND sha256 != ''",
            ],
          },
          {
            category: "registry",
            description: "Windows registry keys and values (persistence, configuration)",
            exampleQueries: [
              "SELECT path, name, data, type FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'",
              "SELECT path, name, data FROM registry WHERE key LIKE '%\\CurrentVersion\\Run%'",
            ],
          },
          {
            category: "users",
            description: "User accounts, login history, group memberships",
            exampleQueries: [
              "SELECT uid, gid, username, directory, shell FROM users",
              "SELECT username, tty, host, time, type FROM last WHERE type = 7 ORDER BY time DESC LIMIT 20",
              "SELECT * FROM logged_in_users",
            ],
          },
          {
            category: "services",
            description: "System services, startup items, scheduled tasks",
            exampleQueries: [
              "SELECT name, display_name, status, start_type, path FROM services WHERE start_type = 'AUTO_START'",
              "SELECT name, action, path, enabled, next_run_time FROM scheduled_tasks WHERE enabled = 1",
              "SELECT name, path, args FROM startup_items",
            ],
          },
          {
            category: "hardware",
            description: "Hardware info, USB devices, PCI devices",
            exampleQueries: [
              "SELECT vendor, model, serial, removable FROM usb_devices",
              "SELECT vendor_id, model_id, vendor, model FROM pci_devices",
              "SELECT hardware_vendor, hardware_model, cpu_brand, physical_memory FROM system_info",
            ],
          },
          {
            category: "software",
            description: "Installed software, browser extensions, packages",
            exampleQueries: [
              "SELECT name, version, publisher FROM programs ORDER BY name",
              "SELECT name, version, publisher FROM programs WHERE publisher LIKE '%unknown%'",
              "SELECT name, version, source FROM deb_packages UNION SELECT name, version, 'rpm' FROM rpm_packages",
            ],
          },
          {
            category: "security",
            description: "Security state, certificates, encryption, patches",
            exampleQueries: [
              "SELECT hotfix_id, description, installed_on FROM patches ORDER BY installed_on DESC LIMIT 20",
              "SELECT common_name, issuer, not_valid_after FROM certificates WHERE not_valid_after < datetime('now')",
              "SELECT encrypted, type, uuid FROM disk_encryption",
            ],
          },
          {
            category: "general",
            description: "System info, uptime, environment variables, OS version",
            exampleQueries: [
              "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info",
              "SELECT days, hours, minutes, total_seconds FROM uptime",
              "SELECT key, value FROM osquery_flags",
            ],
          },
        ];

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { categories, total: categories.length },
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
}
