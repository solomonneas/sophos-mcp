import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Register MCP resources that expose static reference data
 * for Sophos Central workflows.
 */
export function registerResources(server: McpServer): void {
  // -------------------------------------------------------------------------
  // Live Discover Query Library
  // -------------------------------------------------------------------------
  server.resource(
    "live-discover-queries",
    "sophos://live-discover-queries",
    {
      description:
        "Built-in Live Discover query library with osquery SQL templates for endpoint investigation, threat hunting, and forensic analysis",
      mimeType: "application/json",
    },
    async () => {
      const queries = [
        {
          name: "Running Processes",
          category: "processes",
          description: "List all running processes with details",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pid, name, path, cmdline, start_time, uid, on_disk, parent FROM processes ORDER BY start_time DESC",
        },
        {
          name: "Suspicious Process Names",
          category: "processes",
          description: "Find processes matching a suspicious name pattern",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pid, name, path, cmdline, start_time FROM processes WHERE name = '$$processName$$'",
          variables: [{ name: "processName", type: "string", description: "Process name to search for" }],
        },
        {
          name: "Process Tree",
          category: "processes",
          description: "Show parent-child process relationships",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT p.pid, p.name, p.path, p.cmdline, pp.pid AS parent_pid, pp.name AS parent_name, pp.path AS parent_path FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid WHERE p.name != ''",
        },
        {
          name: "Encoded PowerShell Commands",
          category: "processes",
          description: "Detect Base64 encoded PowerShell execution",
          os: ["windows"],
          sql: "SELECT pid, name, cmdline, start_time FROM processes WHERE name = 'powershell.exe' AND (cmdline LIKE '%-enc%' OR cmdline LIKE '%-EncodedCommand%' OR cmdline LIKE '%FromBase64String%')",
        },
        {
          name: "Listening Ports",
          category: "network",
          description: "Show all listening network ports with associated processes",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT lp.pid, p.name, lp.port, lp.address, lp.protocol FROM listening_ports lp JOIN processes p ON lp.pid = p.pid ORDER BY lp.port",
        },
        {
          name: "Non-Standard Listening Ports",
          category: "network",
          description: "Find unusual listening ports that may indicate backdoors",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT lp.pid, p.name, p.path, lp.port, lp.address, lp.protocol FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port NOT IN (80, 443, 22, 53, 135, 139, 445, 3389, 5985, 5986, 8080, 8443) ORDER BY lp.port",
        },
        {
          name: "Active Network Connections",
          category: "network",
          description: "Show current outbound connections with remote addresses",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pos.pid, p.name, pos.remote_address, pos.remote_port, pos.local_port, pos.state FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1' AND pos.remote_address != '::1'",
        },
        {
          name: "Connections to Suspicious Port",
          category: "network",
          description: "Find connections to a specific port (e.g., C2 port)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT pos.pid, p.name, p.path, pos.remote_address, pos.remote_port, pos.state FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_port = $$port$$",
          variables: [{ name: "port", type: "integer", description: "Remote port to search for" }],
        },
        {
          name: "DNS Cache",
          category: "network",
          description: "Dump the local DNS resolver cache",
          os: ["windows"],
          sql: "SELECT name, type, answer FROM dns_cache ORDER BY name",
        },
        {
          name: "Scheduled Tasks",
          category: "services",
          description: "List all scheduled tasks with their actions",
          os: ["windows"],
          sql: "SELECT name, action, path, enabled, next_run_time, last_run_time FROM scheduled_tasks WHERE enabled = 1 ORDER BY next_run_time",
        },
        {
          name: "Autorun/Startup Items",
          category: "services",
          description: "Show all autorun and startup entries (persistence mechanisms)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT name, path, args, source FROM startup_items ORDER BY name",
        },
        {
          name: "Windows Services",
          category: "services",
          description: "List Windows services with their startup configuration",
          os: ["windows"],
          sql: "SELECT name, display_name, status, start_type, path, module_path, user_account FROM services ORDER BY name",
        },
        {
          name: "Recently Modified Files",
          category: "filesystem",
          description: "Find files modified within the last N hours in a directory",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT path, filename, size, mtime, atime FROM file WHERE directory = '$$directory$$' AND mtime > (strftime('%s', 'now') - $$hours$$ * 3600)",
          variables: [
            { name: "directory", type: "string", description: "Directory to search" },
            { name: "hours", type: "integer", description: "Hours to look back", defaultValue: "24" },
          ],
        },
        {
          name: "File Hash Lookup",
          category: "filesystem",
          description: "Get SHA256 hash of a specific file",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT path, sha256, md5 FROM hash WHERE path = '$$filePath$$'",
          variables: [{ name: "filePath", type: "string", description: "Full path to the file" }],
        },
        {
          name: "Temporary Directory Files",
          category: "filesystem",
          description: "List files in common temp directories that may contain malware",
          os: ["windows"],
          sql: "SELECT path, filename, size, mtime FROM file WHERE (directory LIKE 'C:\\Users\\%\\AppData\\Local\\Temp%' OR directory LIKE 'C:\\Windows\\Temp%') AND size > 0 ORDER BY mtime DESC LIMIT 100",
        },
        {
          name: "Installed Software",
          category: "software",
          description: "Complete list of installed software with versions",
          os: ["windows"],
          sql: "SELECT name, version, publisher, install_date FROM programs ORDER BY name",
        },
        {
          name: "Software by Unknown Publisher",
          category: "software",
          description: "Find software from unknown or suspicious publishers",
          os: ["windows"],
          sql: "SELECT name, version, publisher, install_date FROM programs WHERE publisher IS NULL OR publisher = '' OR publisher LIKE '%unknown%'",
        },
        {
          name: "Browser Extensions",
          category: "software",
          description: "List installed browser extensions (Chrome)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT ce.name, ce.identifier, ce.version, ce.description, ce.author, ce.path FROM chrome_extensions ce",
        },
        {
          name: "Run Key Persistence",
          category: "registry",
          description: "Check common Run key registry persistence locations",
          os: ["windows"],
          sql: "SELECT path, name, data, type FROM registry WHERE key IN ('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce')",
        },
        {
          name: "User Accounts",
          category: "users",
          description: "List all local user accounts",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT uid, gid, username, description, directory, shell, type FROM users",
        },
        {
          name: "Recent Logins",
          category: "users",
          description: "Show recent login events",
          os: ["linux", "macOS"],
          sql: "SELECT username, tty, host, time, type FROM last WHERE type = 7 ORDER BY time DESC LIMIT 50",
        },
        {
          name: "Currently Logged In Users",
          category: "users",
          description: "Show users with active sessions",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT user, tty, host, time, pid FROM logged_in_users",
        },
        {
          name: "USB Devices",
          category: "hardware",
          description: "List connected and recently connected USB devices",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT vendor, model, serial, removable, last_connection_time FROM usb_devices ORDER BY last_connection_time DESC",
        },
        {
          name: "System Information",
          category: "general",
          description: "Get comprehensive system information",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT hostname, cpu_brand, cpu_physical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial FROM system_info",
        },
        {
          name: "OS Version",
          category: "general",
          description: "Get detailed OS version information",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT name, version, major, minor, build, platform, codename, arch FROM os_version",
        },
        {
          name: "Disk Encryption Status",
          category: "security",
          description: "Check disk encryption status (BitLocker/FileVault/LUKS)",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT name, uuid, encrypted, type, encryption_status FROM disk_encryption",
        },
        {
          name: "Missing Patches",
          category: "security",
          description: "List recently installed patches to identify missing updates",
          os: ["windows"],
          sql: "SELECT hotfix_id, description, installed_on, installed_by FROM patches ORDER BY installed_on DESC",
        },
        {
          name: "Expired Certificates",
          category: "security",
          description: "Find expired or soon-to-expire certificates",
          os: ["windows", "linux", "macOS"],
          sql: "SELECT common_name, issuer, not_valid_after, not_valid_before, signing_algorithm FROM certificates WHERE not_valid_after < datetime('now', '+30 days') ORDER BY not_valid_after",
        },
      ];

      return {
        contents: [
          {
            uri: "sophos://live-discover-queries",
            mimeType: "application/json",
            text: JSON.stringify({ queries, total: queries.length }, null, 2),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // Policy Reference
  // -------------------------------------------------------------------------
  server.resource(
    "policy-reference",
    "sophos://policy-reference",
    {
      description:
        "Sophos Central policy settings reference — describes available policy types, their settings, and recommended configurations",
      mimeType: "application/json",
    },
    async () => {
      const policyReference = {
        policyTypes: [
          {
            type: "threat-protection",
            description: "Endpoint threat protection settings including real-time scanning, web protection, and behavior monitoring",
            settings: {
              realTimeScanning: {
                description: "Enable/disable real-time file scanning",
                recommended: true,
                options: ["on", "off"],
              },
              behaviorMonitoring: {
                description: "Monitor process behavior for suspicious activity",
                recommended: true,
                options: ["on", "off"],
              },
              webProtection: {
                description: "Block access to malicious websites",
                recommended: true,
                options: ["on", "off", "warn"],
              },
              amsiProtection: {
                description: "Anti-Malware Scan Interface integration",
                recommended: true,
                options: ["on", "off"],
              },
              intrusionPrevention: {
                description: "Network-level exploit prevention",
                recommended: true,
                options: ["on", "off"],
              },
              deepLearning: {
                description: "Deep learning malware detection model",
                recommended: true,
                options: ["on", "off"],
              },
              ransomwareProtection: {
                description: "CryptoGuard ransomware protection",
                recommended: true,
                options: ["on", "off"],
              },
              exploitPrevention: {
                description: "Exploit mitigation techniques",
                recommended: true,
                options: ["on", "off"],
              },
            },
          },
          {
            type: "peripheral-control",
            description: "Control access to USB devices, removable media, and peripherals",
            settings: {
              removableMedia: { description: "Control USB storage devices", options: ["allow", "block", "readOnly"] },
              mtp: { description: "Media Transfer Protocol devices", options: ["allow", "block"] },
              bluetooth: { description: "Bluetooth device control", options: ["allow", "block"] },
              infrared: { description: "Infrared device control", options: ["allow", "block"] },
              wireless: { description: "WiFi adapter control", options: ["allow", "block"] },
            },
          },
          {
            type: "application-control",
            description: "Block or allow specific applications by category or custom rules",
            settings: {
              controlledApplications: { description: "List of controlled application categories" },
              detection: { description: "Detect and report or block", options: ["detectOnly", "block"] },
            },
          },
          {
            type: "data-loss-prevention",
            description: "Protect sensitive data from unauthorized transfer",
            settings: {
              rules: { description: "DLP rules for detecting sensitive content" },
              actions: { description: "Actions on rule match", options: ["allow", "confirm", "block"] },
              transferMethods: { description: "Monitored transfer methods (email, web, USB, etc.)" },
            },
          },
          {
            type: "web-control",
            description: "Category-based web filtering and URL blocking",
            settings: {
              categories: { description: "Website categories with allow/warn/block actions" },
              safeSearch: { description: "Enforce safe search on search engines", options: ["on", "off"] },
              urlTagging: { description: "Log website categories for reporting", options: ["on", "off"] },
            },
          },
          {
            type: "tamper-protection",
            description: "Prevent users and malware from disabling Sophos protection",
            settings: {
              enabled: { description: "Enable tamper protection", recommended: true, options: ["on", "off"] },
              password: { description: "Tamper protection recovery password" },
            },
          },
          {
            type: "update-management",
            description: "Control when and how endpoint agents are updated",
            settings: {
              schedule: { description: "Update schedule (immediate, scheduled, manual)" },
              maintenanceWindow: { description: "Time window for updates" },
              channel: { description: "Update channel", options: ["recommended", "fixed"] },
            },
          },
          {
            type: "windows-firewall",
            description: "Manage Windows Firewall settings through Sophos Central",
            settings: {
              monitorConnections: { description: "Monitor and control network connections" },
              globalRules: { description: "Global firewall rules applied to all endpoints" },
            },
          },
        ],
        enforcementLevels: [
          { level: "recommended", description: "Use Sophos recommended settings (auto-updated)" },
          { level: "custom", description: "Admin-defined custom settings" },
          { level: "disabled", description: "Policy is disabled and not enforced" },
        ],
      };

      return {
        contents: [
          {
            uri: "sophos://policy-reference",
            mimeType: "application/json",
            text: JSON.stringify(policyReference, null, 2),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // MITRE ATT&CK Mappings
  // -------------------------------------------------------------------------
  server.resource(
    "mitre-mappings",
    "sophos://mitre-mappings",
    {
      description:
        "MITRE ATT&CK technique mappings for Sophos EDR/XDR detections — maps detection types to tactics and techniques",
      mimeType: "application/json",
    },
    async () => {
      const mitreMappings = {
        overview:
          "Sophos EDR/XDR detections are mapped to the MITRE ATT&CK framework. " +
          "This resource lists common techniques detected by Sophos and their associated tactics.",
        detectionMappings: [
          {
            detectionType: "behavioralExecution",
            description: "Suspicious process behavior detected",
            techniques: [
              { id: "T1059", name: "Command and Scripting Interpreter", tactics: ["Execution"] },
              { id: "T1059.001", name: "PowerShell", tactics: ["Execution"] },
              { id: "T1059.003", name: "Windows Command Shell", tactics: ["Execution"] },
              { id: "T1204", name: "User Execution", tactics: ["Execution"] },
              { id: "T1204.002", name: "Malicious File", tactics: ["Execution"] },
            ],
          },
          {
            detectionType: "malwareExecution",
            description: "Known malware signature or behavior detected",
            techniques: [
              { id: "T1204.002", name: "Malicious File", tactics: ["Execution"] },
              { id: "T1566.001", name: "Spearphishing Attachment", tactics: ["Initial Access"] },
              { id: "T1027", name: "Obfuscated Files or Information", tactics: ["Defense Evasion"] },
              { id: "T1036", name: "Masquerading", tactics: ["Defense Evasion"] },
            ],
          },
          {
            detectionType: "exploitPrevention",
            description: "Exploit attempt blocked",
            techniques: [
              { id: "T1203", name: "Exploitation for Client Execution", tactics: ["Execution"] },
              { id: "T1068", name: "Exploitation for Privilege Escalation", tactics: ["Privilege Escalation"] },
              { id: "T1189", name: "Drive-by Compromise", tactics: ["Initial Access"] },
              { id: "T1211", name: "Exploitation for Defense Evasion", tactics: ["Defense Evasion"] },
            ],
          },
          {
            detectionType: "credential",
            description: "Credential theft or access attempt detected",
            techniques: [
              { id: "T1003", name: "OS Credential Dumping", tactics: ["Credential Access"] },
              { id: "T1003.001", name: "LSASS Memory", tactics: ["Credential Access"] },
              { id: "T1110", name: "Brute Force", tactics: ["Credential Access"] },
              { id: "T1555", name: "Credentials from Password Stores", tactics: ["Credential Access"] },
              { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactics: ["Credential Access"] },
            ],
          },
          {
            detectionType: "lateralMovement",
            description: "Lateral movement activity detected",
            techniques: [
              { id: "T1021", name: "Remote Services", tactics: ["Lateral Movement"] },
              { id: "T1021.001", name: "Remote Desktop Protocol", tactics: ["Lateral Movement"] },
              { id: "T1021.002", name: "SMB/Windows Admin Shares", tactics: ["Lateral Movement"] },
              { id: "T1021.003", name: "Distributed Component Object Model", tactics: ["Lateral Movement"] },
              { id: "T1021.006", name: "Windows Remote Management", tactics: ["Lateral Movement"] },
              { id: "T1570", name: "Lateral Tool Transfer", tactics: ["Lateral Movement"] },
            ],
          },
          {
            detectionType: "commandAndControl",
            description: "Command and control communication detected",
            techniques: [
              { id: "T1071", name: "Application Layer Protocol", tactics: ["Command and Control"] },
              { id: "T1071.001", name: "Web Protocols", tactics: ["Command and Control"] },
              { id: "T1071.004", name: "DNS", tactics: ["Command and Control"] },
              { id: "T1573", name: "Encrypted Channel", tactics: ["Command and Control"] },
              { id: "T1572", name: "Protocol Tunneling", tactics: ["Command and Control"] },
              { id: "T1105", name: "Ingress Tool Transfer", tactics: ["Command and Control"] },
            ],
          },
          {
            detectionType: "dataExfiltration",
            description: "Data exfiltration activity detected",
            techniques: [
              { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactics: ["Exfiltration"] },
              { id: "T1041", name: "Exfiltration Over C2 Channel", tactics: ["Exfiltration"] },
              { id: "T1567", name: "Exfiltration Over Web Service", tactics: ["Exfiltration"] },
              { id: "T1537", name: "Transfer Data to Cloud Account", tactics: ["Exfiltration"] },
            ],
          },
          {
            detectionType: "evasion",
            description: "Defense evasion technique detected",
            techniques: [
              { id: "T1055", name: "Process Injection", tactics: ["Defense Evasion", "Privilege Escalation"] },
              { id: "T1055.001", name: "Dynamic-link Library Injection", tactics: ["Defense Evasion"] },
              { id: "T1218", name: "System Binary Proxy Execution", tactics: ["Defense Evasion"] },
              { id: "T1562", name: "Impair Defenses", tactics: ["Defense Evasion"] },
              { id: "T1070", name: "Indicator Removal", tactics: ["Defense Evasion"] },
              { id: "T1112", name: "Modify Registry", tactics: ["Defense Evasion"] },
            ],
          },
          {
            detectionType: "pua",
            description: "Potentially Unwanted Application detected",
            techniques: [
              { id: "T1176", name: "Browser Extensions", tactics: ["Persistence"] },
              { id: "T1219", name: "Remote Access Software", tactics: ["Command and Control"] },
            ],
          },
          {
            detectionType: "webThreat",
            description: "Web-based threat detected and blocked",
            techniques: [
              { id: "T1189", name: "Drive-by Compromise", tactics: ["Initial Access"] },
              { id: "T1566.002", name: "Spearphishing Link", tactics: ["Initial Access"] },
              { id: "T1598", name: "Phishing for Information", tactics: ["Reconnaissance"] },
            ],
          },
        ],
        tactics: [
          "Reconnaissance",
          "Resource Development",
          "Initial Access",
          "Execution",
          "Persistence",
          "Privilege Escalation",
          "Defense Evasion",
          "Credential Access",
          "Discovery",
          "Lateral Movement",
          "Collection",
          "Command and Control",
          "Exfiltration",
          "Impact",
        ],
      };

      return {
        contents: [
          {
            uri: "sophos://mitre-mappings",
            mimeType: "application/json",
            text: JSON.stringify(mitreMappings, null, 2),
          },
        ],
      };
    }
  );
}
