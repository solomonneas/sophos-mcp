// ============================================================================
// Sophos Central Type Definitions
// ============================================================================

// --- API Response Wrappers ---

/** Standard paginated response from the Sophos Central REST API */
export interface SophosPaginatedResponse<T> {
  items: T[];
  pages: {
    current: number;
    size: number;
    total: number;
    items: number;
    maxSize: number;
  };
}

/** Standard single-object response */
export interface SophosResponse<T> {
  id: string;
  [key: string]: unknown;
}

/** Error response from the API */
export interface SophosError {
  error: string;
  correlationId: string;
  requestId: string;
  createdAt: string;
  code?: string;
  message?: string;
}

/** OAuth2 token response */
export interface SophosTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  errorCode?: string;
  message?: string;
}

/** Whoami response for tenant discovery */
export interface SophosWhoamiResponse {
  id: string;
  idType: "tenant" | "partner" | "organization";
  apiHosts: {
    global: string;
    dataRegion: string;
  };
}

// --- Endpoints ---

/** Endpoint health status */
export type EndpointHealthStatus = "good" | "suspicious" | "bad" | "unknown";

/** Endpoint type */
export type EndpointType = "computer" | "server" | "securityVm";

/** Endpoint OS platform */
export type EndpointOSPlatform = "windows" | "linux" | "macOS";

/** Endpoint lockdown status */
export type LockdownStatus = "creatingWhitelist" | "installing" | "locked" | "notInstalled" | "registering" | "starting" | "stopping" | "unavailable" | "uninstalled" | "unlocked";

/** Endpoint isolation status */
export type IsolationStatus = "isolated" | "notIsolated";

/** Tamper protection status */
export type TamperProtectionStatus = "enabled" | "disabled";

/** Installed Sophos product on an endpoint */
export interface EndpointProduct {
  name: string;
  status: string;
  version: string;
}

/** Endpoint operating system details */
export interface EndpointOS {
  isServer: boolean;
  platform: EndpointOSPlatform;
  name: string;
  majorVersion: number;
  minorVersion: number;
  build?: number;
}

/** Endpoint health details */
export interface EndpointHealth {
  overall: EndpointHealthStatus;
  threats: {
    status: EndpointHealthStatus;
  };
  services: {
    status: EndpointHealthStatus;
    serviceDetails: Array<{
      name: string;
      status: string;
    }>;
  };
}

/** Endpoint network interface */
export interface EndpointNetworkInterface {
  macAddress: string;
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  type: string;
}

/** Endpoint group membership */
export interface EndpointGroup {
  id: string;
  name: string;
}

/** Software installed on an endpoint */
export interface EndpointSoftware {
  name: string;
  version: string;
  publisher?: string;
  installDate?: string;
  size?: number;
}

/** Sophos Central Endpoint */
export interface Endpoint {
  id: string;
  type: EndpointType;
  tenant: {
    id: string;
  };
  hostname: string;
  health: EndpointHealth;
  os: EndpointOS;
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  macAddresses: string[];
  associatedPerson?: {
    id: string;
    name: string;
    viaLogin: string;
  };
  assignedProducts: EndpointProduct[];
  lastSeenAt: string;
  firstSeenAt?: string;
  tamperProtectionEnabled: boolean;
  lockdown: {
    status: LockdownStatus;
    updateStatus: string;
  };
  isolation?: {
    status: IsolationStatus;
    adminIsolated: boolean;
    selfIsolated: boolean;
  };
  group?: EndpointGroup;
  cloud?: {
    provider: string;
    instanceId: string;
  };
  online: boolean;
}

// --- Alerts ---

/** Alert severity */
export type AlertSeverity = "low" | "medium" | "high";

/** Alert category */
export type AlertCategory =
  | "azure"
  | "adSync"
  | "applicationControl"
  | "appReputation"
  | "blockListed"
  | "connectivity"
  | "cwg"
  | "denc"
  | "downloadReputation"
  | "endpointFirewall"
  | "fakeAV"
  | "general"
  | "iaas"
  | "iaasAzure"
  | "isolation"
  | "malware"
  | "mtr"
  | "mobiles"
  | "policy"
  | "protection"
  | "pua"
  | "runtimeDetections"
  | "security"
  | "smc"
  | "systemHealth"
  | "uav"
  | "utm"
  | "virt"
  | "wireless"
  | "xgEmail";

/** Sophos product that generated the alert */
export type AlertProduct =
  | "endpoint"
  | "server"
  | "mobile"
  | "encryption"
  | "emailGateway"
  | "webGateway"
  | "phishThreat"
  | "wireless"
  | "iaas"
  | "firewall";

/** Managed agent info within an alert */
export interface AlertManagedAgent {
  id: string;
  type: EndpointType;
  name?: string;
}

/** Sophos Central Alert */
export interface Alert {
  id: string;
  allowedActions: string[];
  category: AlertCategory;
  description: string;
  groupKey: string;
  managedAgent?: AlertManagedAgent;
  person?: {
    id: string;
    name?: string;
  };
  product: AlertProduct;
  raisedAt: string;
  severity: AlertSeverity;
  tenant: {
    id: string;
    name?: string;
  };
  type: string;
  data?: Record<string, unknown>;
}

// --- Detections ---

/** Detection severity */
export type DetectionSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Detection type */
export type DetectionType =
  | "behavioralExecution"
  | "malwareExecution"
  | "exploitPrevention"
  | "webThreat"
  | "applicationControl"
  | "pua"
  | "runtimeDetection"
  | "credential"
  | "lateralMovement"
  | "commandAndControl"
  | "dataExfiltration"
  | "evasion";

/** MITRE ATT&CK technique mapping */
export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  url: string;
}

/** EDR/XDR Detection */
export interface Detection {
  id: string;
  type: DetectionType;
  severity: DetectionSeverity;
  summary: string;
  description: string;
  detectedAt: string;
  resolvedAt?: string;
  endpoint: {
    id: string;
    hostname: string;
    ipAddress?: string;
    os?: string;
  };
  process?: {
    pid: number;
    name: string;
    path: string;
    commandLine?: string;
    sha256?: string;
    parentPid?: number;
    parentName?: string;
  };
  user?: {
    id?: string;
    name: string;
    domain?: string;
  };
  mitreTechniques: MitreTechnique[];
  indicators: Array<{
    type: string;
    value: string;
    description?: string;
  }>;
  rawData?: Record<string, unknown>;
}

/** Threat case (grouped detections) */
export type ThreatCaseStatus = "new" | "investigating" | "inProgress" | "containment" | "resolved" | "closed";

export interface ThreatCase {
  id: string;
  name: string;
  status: ThreatCaseStatus;
  severity: DetectionSeverity;
  description: string;
  createdAt: string;
  updatedAt: string;
  assignee?: {
    id: string;
    name: string;
  };
  detectionCount: number;
  endpointCount: number;
  mitreTechniques: MitreTechnique[];
  tenant: {
    id: string;
  };
}

// --- Events ---

/** Security event type */
export type EventType =
  | "Event::Endpoint::Application::Blocked"
  | "Event::Endpoint::CoreRestore::Failed"
  | "Event::Endpoint::DataLossPrevention"
  | "Event::Endpoint::Threat::CleanedUp"
  | "Event::Endpoint::Threat::Detected"
  | "Event::Endpoint::Threat::NotBlocked"
  | "Event::Endpoint::Threat::PuaDetected"
  | "Event::Endpoint::Threat::PuaCleanedUp"
  | "Event::Endpoint::UpdateFailure"
  | "Event::Endpoint::UpdateSuccess"
  | "Event::Endpoint::WebControlViolation"
  | "Event::Endpoint::WebFilteringBlocked"
  | "Event::Firewall::Allowed"
  | "Event::Firewall::Blocked"
  | "Event::Mobile::ComplianceViolation"
  | "Event::Endpoint::SavScanComplete"
  | string;

/** Security event severity */
export type EventSeverity = "none" | "low" | "medium" | "high" | "critical";

/** Sophos Central Security Event */
export interface SecurityEvent {
  id: string;
  type: EventType;
  severity: EventSeverity;
  name: string;
  location: string;
  group: string;
  when: string;
  source: string;
  endpoint?: {
    id: string;
    hostname: string;
    type: EndpointType;
  };
  user?: {
    id: string;
    name: string;
  };
  customerData?: Record<string, unknown>;
  ioc?: string;
  iocType?: string;
}

/** Audit log entry */
export interface AuditLogEntry {
  id: string;
  type: string;
  description: string;
  timestamp: string;
  actor: {
    id: string;
    name: string;
    type: "user" | "system" | "api";
  };
  target?: {
    id: string;
    name: string;
    type: string;
  };
  result: "success" | "failure";
  details?: Record<string, unknown>;
  sourceIp?: string;
}

// --- Policies ---

/** Policy type */
export type PolicyType =
  | "threat-protection"
  | "peripheral-control"
  | "application-control"
  | "data-loss-prevention"
  | "tamper-protection"
  | "web-control"
  | "windows-firewall"
  | "server-threat-protection"
  | "server-peripheral-control"
  | "server-lockdown"
  | "server-application-control"
  | "update-management";

/** Policy enforcement level */
export type PolicyEnforcement = "recommended" | "custom" | "disabled";

/** Policy assignment scope */
export interface PolicyScope {
  type: "endpoint" | "server" | "group";
  ids: string[];
}

/** Scanning exclusion */
export interface ScanningExclusion {
  id: string;
  type: "path" | "process" | "extension" | "posixPath" | "virtualPath" | "amsi";
  value: string;
  description?: string;
  scanMode: "onDemandAndOnAccess" | "onAccess" | "onDemand";
  comment?: string;
}

/** Sophos Central Policy */
export interface Policy {
  id: string;
  name: string;
  type: PolicyType;
  enabled: boolean;
  enforcement: PolicyEnforcement;
  priority: number;
  settings: Record<string, unknown>;
  appliesTo: PolicyScope;
  createdAt: string;
  updatedAt: string;
  lockedBy?: string;
}

// --- Tenants ---

/** Tenant billing type */
export type TenantBillingType = "trial" | "usage" | "term";

/** Tenant status */
export type TenantStatus = "active" | "deactivated" | "suspended";

/** License info */
export interface TenantLicense {
  id: string;
  product: string;
  type: string;
  quantity: number;
  usedQuantity: number;
  expiresAt?: string;
  status: "active" | "expired" | "suspended";
}

/** Managed Tenant */
export interface Tenant {
  id: string;
  name: string;
  dataGeography: string;
  dataRegion: string;
  billingType: TenantBillingType;
  status: TenantStatus;
  apiHost: string;
  createdAt: string;
  contact?: {
    firstName: string;
    lastName: string;
    email: string;
    phone?: string;
  };
  licenses: TenantLicense[];
}

/** Tenant health overview */
export interface TenantHealth {
  tenantId: string;
  tenantName: string;
  endpointCount: number;
  protectedEndpoints: number;
  unprotectedEndpoints: number;
  healthScore: number;
  threats: {
    active: number;
    resolved: number;
  };
  compliance: {
    compliant: number;
    nonCompliant: number;
  };
  lastUpdated: string;
}

// --- Live Discover ---

/** Live Discover query status */
export type LiveDiscoverQueryStatus = "pending" | "started" | "finished" | "failed" | "canceled";

/** Live Discover query category */
export type LiveDiscoverCategory =
  | "processes"
  | "network"
  | "filesystem"
  | "registry"
  | "users"
  | "services"
  | "hardware"
  | "software"
  | "security"
  | "general"
  | "custom";

/** Saved Live Discover query */
export interface SavedLiveDiscoverQuery {
  id: string;
  name: string;
  description: string;
  category: LiveDiscoverCategory;
  sql: string;
  supportedOSes: EndpointOSPlatform[];
  variables?: Array<{
    name: string;
    type: string;
    description: string;
    defaultValue?: string;
  }>;
  createdAt: string;
  updatedAt: string;
  builtIn: boolean;
}

/** Live Discover query run */
export interface LiveDiscoverQueryRun {
  id: string;
  queryId?: string;
  sql: string;
  status: LiveDiscoverQueryStatus;
  endpoints: Array<{
    id: string;
    hostname: string;
    status: LiveDiscoverQueryStatus;
  }>;
  createdAt: string;
  finishedAt?: string;
  resultCount?: number;
}

/** Live Discover query result */
export interface LiveDiscoverResult {
  queryRunId: string;
  endpointId: string;
  hostname: string;
  columns: string[];
  rows: Array<Record<string, string | number | boolean | null>>;
}
