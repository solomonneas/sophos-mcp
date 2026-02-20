# Sophos Central MCP Server

[![TypeScript 5.7](https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green?logo=node.js)](https://nodejs.org/)
[![MCP SDK](https://img.shields.io/badge/MCP-1.x-purple)](https://modelcontextprotocol.io)
[![Sophos](https://img.shields.io/badge/Sophos-Central-blue)](https://www.sophos.com/en-us/products/sophos-central)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that provides AI assistants with access to [Sophos Central](https://www.sophos.com/en-us/products/sophos-central), a unified cloud security management platform. Manage endpoints, investigate alerts, analyze EDR/XDR detections, run Live Discover queries, and audit security policies.

## Features

### Endpoints
- List, search, and inspect endpoints by hostname, IP, OS, health status
- Network isolation and un-isolation for incident response
- On-demand scan triggering
- Software inventory retrieval

### Alerts
- List and filter alerts by severity, category, product, date range
- Acknowledge and resolve alerts with actions taken
- View available response actions per alert

### EDR/XDR Detections
- List detections with MITRE ATT&CK technique mappings
- Threat case management (grouped related detections)
- Detection-to-case correlation

### Security Events
- Search events by type, severity, endpoint, date range
- Event type catalog (malware, PUA, web filter, etc.)
- Admin audit log access

### Policies
- List endpoint, server, and firewall policies
- Inspect individual policy configurations
- Review global and policy-specific exclusions

### Tenant Management
- Multi-tenant listing (MSP/partner view)
- Tenant details and license information
- Overall tenant security health scoring

### Live Discover (osquery)
- Execute Live Discover queries on endpoints
- Saved query library management
- Query result retrieval
- Query category browsing

## Architecture

```text
┌────────────────────────────────────────┐
│           MCP Client (LLM)             │
└──────────────┬─────────────────────────┘
               │ MCP Protocol (stdio)
┌──────────────▼─────────────────────────┐
│          sophos-mcp server             │
│                                        │
│  ┌──────────┐  ┌────────────────────┐  │
│  │ Prompts  │  │    Resources       │  │
│  │ 4 guides │  │ queries, policies, │  │
│  │          │  │ MITRE mappings     │  │
│  └──────────┘  └────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │            Tools                  │  │
│  │  endpoints │ alerts │ detections  │  │
│  │  events │ policies │ tenants     │  │
│  │  live-discover                    │  │
│  └──────────────┬───────────────────┘  │
│                 │                       │
│  ┌──────────────▼───────────────────┐  │
│  │      Sophos Central API Client   │  │
│  │      (OAuth2 + REST)             │  │
│  └──────────────┬───────────────────┘  │
└──────────────────┼─────────────────────┘
                   │ HTTPS
┌──────────────────▼─────────────────────┐
│       Sophos Central Platform API      │
│  https://api.central.sophos.com        │
└────────────────────────────────────────┘
```

## Installation

```bash
git clone https://github.com/solomonneas/sophos-mcp.git
cd sophos-mcp
npm install
npm run build
```

## Configuration

Sophos Central uses OAuth2 with client credentials. Set environment variables:

```bash
export SOPHOS_CLIENT_ID="your-client-id"
export SOPHOS_CLIENT_SECRET="your-client-secret"
export SOPHOS_TENANT_ID="your-tenant-id"   # optional for single-tenant
```

Or use a `.env` file:

```env
SOPHOS_CLIENT_ID=your-client-id
SOPHOS_CLIENT_SECRET=your-client-secret
SOPHOS_TENANT_ID=your-tenant-id
```

### Getting API Credentials

1. Log in to [Sophos Central](https://central.sophos.com)
2. Go to **Global Settings > API Credentials Management**
3. Click **Add Credential** and assign a role
4. Copy the Client ID and Client Secret

## MCP Client Configuration

### Claude Desktop

```json
{
  "mcpServers": {
    "sophos": {
      "command": "node",
      "args": ["path/to/sophos-mcp/dist/index.js"],
      "env": {
        "SOPHOS_CLIENT_ID": "your-client-id",
        "SOPHOS_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

## Tool Reference

| Tool | Description |
|------|-------------|
| `list_endpoints` | Search endpoints by hostname, IP, health, OS, group |
| `get_endpoint` | Full endpoint details with agent info and products |
| `isolate_endpoint` | Network isolate an endpoint (incident response) |
| `unisolate_endpoint` | Remove network isolation |
| `scan_endpoint` | Trigger on-demand scan |
| `get_endpoint_software` | List installed software on endpoint |
| `list_alerts` | Get alerts with severity/category/product filters |
| `get_alert` | Full alert details with description |
| `acknowledge_alert` | Mark alert as acknowledged |
| `resolve_alert` | Resolve/close alert with action taken |
| `get_alert_actions` | List available response actions |
| `list_detections` | EDR/XDR detections with filters |
| `get_detection` | Full detection with MITRE ATT&CK mapping |
| `get_threat_cases` | Grouped related detections |
| `get_case_detections` | All detections in a threat case |
| `update_case_status` | Update threat case status |
| `search_events` | Search security events by type/severity/date |
| `get_event` | Full event details |
| `list_event_types` | Available event type catalog |
| `get_audit_logs` | Admin audit trail |
| `list_policies` | List endpoint/server/firewall policies |
| `get_policy` | Full policy configuration |
| `get_policy_settings` | Specific settings within a policy |
| `list_exclusions` | Global and policy-specific exclusions |
| `list_tenants` | List managed tenants (MSP view) |
| `get_tenant` | Tenant details and license info |
| `get_tenant_health` | Overall tenant security health score |
| `run_query` | Execute Live Discover query on endpoints |
| `list_saved_queries` | List saved Live Discover queries |
| `get_query_results` | Retrieve completed query results |
| `list_query_categories` | Available query categories |

## Live Discover Query Examples

```sql
-- Running processes
SELECT pid, name, path, cmdline, start_time FROM processes WHERE name = 'suspicious.exe';

-- Listening ports (non-standard)
SELECT pid, port, address, protocol FROM listening_ports WHERE port NOT IN (80, 443, 22);

-- Scheduled tasks
SELECT name, action, path, enabled FROM scheduled_tasks WHERE enabled = 1;

-- Installed software from unknown publishers
SELECT name, version, publisher FROM programs WHERE publisher LIKE '%unknown%';

-- Active network connections to suspicious port
SELECT pid, remote_address, remote_port, state FROM socket_events WHERE remote_port = 4444;

-- File hash lookup
SELECT path, sha256 FROM hash WHERE path = '/usr/bin/suspicious';

-- Recently modified executables
SELECT path, filename, size, mtime FROM file WHERE path LIKE '/tmp/%' AND filename LIKE '%.exe';
```

## Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-endpoint` | Guided endpoint investigation workflow |
| `threat-hunt` | Hunt for IOCs across endpoints via Live Discover |
| `incident-response` | Step-by-step IR: contain, investigate, remediate |
| `health-audit` | Review tenant/endpoint security posture |

## Resources

| URI | Description |
|-----|-------------|
| `sophos://live-discover-queries` | Built-in Live Discover query library |
| `sophos://policy-reference` | Policy settings reference |
| `sophos://mitre-mappings` | MITRE ATT&CK technique mappings |

## Development

```bash
npm run build    # Compile TypeScript
npm run dev      # Watch mode
npm run test     # Run tests
npm run lint     # Lint check
```

## License

MIT
