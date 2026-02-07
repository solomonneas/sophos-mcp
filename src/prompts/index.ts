import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

/**
 * Register MCP prompts for common Sophos Central investigation
 * and threat-hunting workflows.
 */
export function registerPrompts(server: McpServer): void {
  // -------------------------------------------------------------------------
  // investigate-endpoint
  // -------------------------------------------------------------------------
  server.prompt(
    "investigate-endpoint",
    "Guided workflow for investigating a suspicious endpoint in Sophos Central",
    {
      endpoint_id: z
        .string()
        .describe("The endpoint ID to investigate"),
    },
    ({ endpoint_id }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
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
              "12. Document findings and actions taken",
            ].join("\n"),
          },
        },
      ],
    })
  );

  // -------------------------------------------------------------------------
  // threat-hunt
  // -------------------------------------------------------------------------
  server.prompt(
    "threat-hunt",
    "Hunt for indicators of compromise across endpoints using Sophos Live Discover",
    {
      indicator: z
        .string()
        .describe("IOC to hunt for (IP, domain, hash, filename, or process name)"),
      indicator_type: z
        .string()
        .optional()
        .describe("Type of indicator: ip, domain, hash, filename, process (auto-detected if omitted)"),
    },
    ({ indicator, indicator_type }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
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
              "9. Document all findings with endpoint IDs and timestamps",
            ].join("\n"),
          },
        },
      ],
    })
  );

  // -------------------------------------------------------------------------
  // incident-response
  // -------------------------------------------------------------------------
  server.prompt(
    "incident-response",
    "Step-by-step incident response workflow: contain, investigate, remediate",
    {
      incident_description: z
        .string()
        .describe("Brief description of the incident"),
    },
    ({ incident_description }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
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
              "17. Identify detection gaps and recommend improvements",
            ].join("\n"),
          },
        },
      ],
    })
  );

  // -------------------------------------------------------------------------
  // health-audit
  // -------------------------------------------------------------------------
  server.prompt(
    "health-audit",
    "Audit tenant and endpoint security health posture",
    {},
    () => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
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
              "    - Recommended actions (prioritized)",
            ].join("\n"),
          },
        },
      ],
    })
  );
}
