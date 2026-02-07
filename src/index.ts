import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
import { SophosClient } from "./client.js";
import { registerEndpointTools } from "./tools/endpoints.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerDetectionTools } from "./tools/detections.js";
import { registerEventTools } from "./tools/events.js";
import { registerPolicyTools } from "./tools/policies.js";
import { registerTenantTools } from "./tools/tenants.js";
import { registerLiveDiscoverTools } from "./tools/live-discover.js";
import { registerResources } from "./resources/index.js";
import { registerPrompts } from "./prompts/index.js";

async function main(): Promise<void> {
  const config = getConfig();
  const client = new SophosClient(config);

  const server = new McpServer({
    name: "sophos-mcp",
    version: "1.0.0",
    description:
      "MCP server for Sophos Central — endpoint management, EDR/XDR detections, alerts, Live Discover queries, and security policy management",
  });

  // Register tools
  registerEndpointTools(server, client);
  registerAlertTools(server, client);
  registerDetectionTools(server, client);
  registerEventTools(server, client);
  registerPolicyTools(server, client);
  registerTenantTools(server, client);
  registerLiveDiscoverTools(server, client);

  // Register resources and prompts
  registerResources(server);
  registerPrompts(server);

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Sophos Central MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
