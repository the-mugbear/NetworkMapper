import axios from 'axios';

import { getApiBaseUrl } from '../utils/apiUrl';

const API_BASE_URL = getApiBaseUrl();

// API Configuration
// Base URL: ${API_BASE_URL}/api/v1
// Environment URL: ${process.env.REACT_APP_API_URL}
// Current Location: ${window.location.href}

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor to include authentication token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor to handle authentication errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token is invalid or expired
      localStorage.removeItem('auth_token');
      localStorage.removeItem('auth_user');
      // Redirect to login page
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export interface ScanVulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanPortBreakdown {
  unique_ports: number;
  open_tcp_ports: number;
  open_udp_ports: number;
}

export interface Scan {
  id: number;
  filename: string;
  scan_type: string | null;
  tool_name: string | null;
  created_at: string;
  total_hosts: number;
  up_hosts: number;
  total_ports: number;
  open_ports: number;
  port_breakdown?: ScanPortBreakdown | null;
  vulnerability_summary?: ScanVulnerabilitySummary | null;
}

export interface HostVulnerabilitySummary {
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface HostVulnerability {
  id: number;
  plugin_id: string | null;
  title: string | null;
  severity: string | null;
  source: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cve_id: string | null;
  scan_id: number | null;
  port_id: number | null;
  port_number: number | null;
  protocol: string | null;
  service_name: string | null;
  exploitable: boolean | null;
  first_seen: string | null;
  last_seen: string | null;
  solution: string | null;
}

export interface Host {
  id: number;
  ip_address: string;
  hostname: string | null;
  state: string | null;
  os_name: string | null;
  ports: Port[];
  vulnerability_summary?: HostVulnerabilitySummary;
  vulnerabilities?: HostVulnerability[];
  follow?: HostFollowInfo | null;
  notes?: HostNote[];
  note_count?: number;
}

export type FollowStatus = 'watching' | 'in_review' | 'reviewed';
export type NoteStatus = 'open' | 'in_progress' | 'resolved';

export interface HostFollowInfo {
  status: FollowStatus;
  created_at: string;
  updated_at?: string | null;
}

export interface HostNote {
  id: number;
  body: string;
  status: NoteStatus;
  author_id: number;
  author_name: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface Port {
  id: number;
  port_number: number;
  protocol: string;
  state: string | null;
  service_name: string | null;
  service_product: string | null;
  service_version: string | null;
}

export interface SubnetStats {
  id: number;
  cidr: string;
  scope_name: string;
  description: string | null;
  host_count: number;
  total_addresses?: number;
  usable_addresses?: number;
  utilization_percentage?: number;
  risk_level?: string;
  network_address?: string;
  is_private?: boolean;
}

export interface ParseError {
  id: number;
  filename: string;
  file_type: string | null;
  file_size: number | null;
  error_type: string;
  error_message: string;
  error_details: any;
  file_preview: string | null;
  user_message: string | null;
  status: string;
  created_at: string;
  updated_at: string | null;
}

export interface ParseErrorSummary {
  id: number;
  filename: string;
  file_type: string | null;
  error_type: string;
  user_message: string | null;
  status: string;
  created_at: string;
}

export interface HostConflict {
  id: number;
  field_name: string;
  confidence_score: number;
  scan_type: string;
  data_source: string;
  method: string;
  scan_id: number;
  updated_at: string;
  additional_factors?: any;
}

export interface VulnerabilityStats {
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  hosts_with_vulnerabilities: number;
}

export interface DashboardStats {
  total_scans: number;
  total_hosts: number;
  total_ports: number;
  up_hosts: number;
  open_ports: number;
  total_subnets: number;
  recent_scans: Scan[];
  subnet_stats: SubnetStats[];
  vulnerability_stats?: VulnerabilityStats;
  note_activity?: NoteActivitySummary;
}
export interface NoteActivityEntry {
  note_id: number;
  host_id: number;
  ip_address: string;
  hostname: string | null;
  status: NoteStatus;
  preview: string;
  created_at: string;
  updated_at?: string | null;
}

export interface NoteActivitySummary {
  total_notes: number;
  active_host_count: number;
  following_count: number;
  recent_notes: NoteActivityEntry[];
}

export interface Scope {
  id: number;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string | null;
  subnets: Subnet[];
}

export interface ScopeSummary {
  id: number;
  name: string;
  description: string | null;
  created_at: string;
  subnet_count: number;
}

export interface Subnet {
  id: number;
  scope_id: number;
  cidr: string;
  description: string | null;
  created_at: string;
}

export interface SubnetFileUploadResponse {
  message: string;
  scope_id: number;
  subnets_added: number;
  filename: string;
}

export interface HostSubnetMapping {
  id: number;
  host_id: number;
  subnet_id: number;
  created_at: string;
  subnet: Subnet;
}

export interface EyewitnessResult {
  id: number;
  scan_id: number;
  url: string;
  protocol: string | null;
  port: number | null;
  ip_address: string | null;
  title: string | null;
  server_header: string | null;
  content_length: number | null;
  screenshot_path: string | null;
  response_code: number | null;
  page_text: string | null;
  created_at: string;
}

export interface DNSRecord {
  id: number;
  domain: string;
  record_type: string;
  value: string;
  ttl: number | null;
  created_at: string;
  updated_at: string | null;
}

export interface OutOfScopeHost {
  id: number;
  scan_id: number;
  ip_address: string;
  hostname: string | null;
  ports: any;
  tool_source: string | null;
  reason: string | null;
  created_at: string;
}

export interface FileUploadResponse {
  job_id: number;
  filename: string;
  status: string;
  message: string;
  scan_id: number | null;
  parse_error_id?: number | null;
}

export interface IngestionJob {
  id: number;
  filename: string;
  original_filename: string;
  status: string;
  message?: string;
  error_message?: string;
  tool_name?: string;
  file_size?: number;
  scan_id?: number | null;
  parse_error_id?: number | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface PortOfInterestSummary {
  port: number;
  protocol: string;
  label: string;
  category: string;
  weight: number;
  open_host_count: number;
  rationale: string;
  recommended_action: string;
}

export interface PortOfInterestHostEntry {
  port: number;
  protocol: string;
  label: string;
  service: string;
  weight: number;
  category: string;
}

export interface HostRiskExposure {
  host_id: number;
  ip_address: string;
  hostname: string | null;
  ports_of_interest: PortOfInterestHostEntry[];
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number;
  port_score: number;
  vulnerability_score: number;
}

export interface VulnerabilityHotspot {
  host_id: number;
  ip_address: string;
  hostname: string | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number;
}

export interface RiskInsightResponse {
  ports_of_interest: {
    summary: PortOfInterestSummary[];
    top_hosts: HostRiskExposure[];
  };
  vulnerability_hotspots: VulnerabilityHotspot[];
}

// Upload API
interface DnsConfig {
  enabled: boolean;
  server?: string;
}

export const uploadFile = async (
  file: File,
  dnsConfig: DnsConfig = { enabled: false }
): Promise<FileUploadResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  if (dnsConfig.enabled) {
    formData.append('enrich_dns', 'true');
    if (dnsConfig.server) {
      formData.append('dns_server', dnsConfig.server);
    }
  }
  
  const response = await api.post<FileUploadResponse>('/upload/', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  
  return response.data;
};

export const getIngestionJob = async (jobId: number): Promise<IngestionJob> => {
  const response = await api.get(`/upload/jobs/${jobId}`);
  return response.data;
};

export const getRiskInsights = async (): Promise<RiskInsightResponse> => {
  const response = await api.get('/dashboard/risk-insights');
  return response.data;
};

export const getRecentIngestionJobs = async (limit = 5): Promise<IngestionJob[]> => {
  const response = await api.get(`/upload/jobs?limit=${limit}`);
  return response.data;
};

export const followHost = async (hostId: number, status: FollowStatus): Promise<HostFollowInfo> => {
  const response = await api.post(`/hosts/${hostId}/follow`, { status });
  return response.data;
};

export const unfollowHost = async (hostId: number): Promise<void> => {
  await api.delete(`/hosts/${hostId}/follow`);
};

export const getHostNotes = async (hostId: number): Promise<HostNote[]> => {
  const response = await api.get(`/hosts/${hostId}/notes`);
  return response.data;
};

export const createHostNote = async (
  hostId: number,
  payload: { body: string; status?: NoteStatus },
): Promise<HostNote> => {
  const response = await api.post(`/hosts/${hostId}/notes`, payload);
  return response.data;
};

export const updateHostNote = async (
  hostId: number,
  noteId: number,
  payload: { body?: string; status?: NoteStatus },
): Promise<HostNote> => {
  const response = await api.patch(`/hosts/${hostId}/notes/${noteId}`, payload);
  return response.data;
};

export const deleteHostNote = async (hostId: number, noteId: number): Promise<void> => {
  await api.delete(`/hosts/${hostId}/notes/${noteId}`);
};

// Scans API
export const getScans = async (skip = 0, limit = 100): Promise<Scan[]> => {
  const response = await api.get(`/scans/?skip=${skip}&limit=${limit}`);
  return response.data;
};

export const getScan = async (scanId: number) => {
  const response = await api.get(`/scans/${scanId}`);
  return response.data;
};

export const deleteScan = async (scanId: number) => {
  const response = await api.delete(`/scans/${scanId}`);
  return response.data;
};

// Hosts API
export const getHosts = async (params: {
  scan_id?: number;
  state?: string;
  search?: string;
  ports?: string;
  services?: string;
  port_states?: string;
  has_open_ports?: boolean;
  os_filter?: string;
  skip?: number;
  limit?: number;
}): Promise<Host[]> => {
  const queryParams = new URLSearchParams();
  
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined) {
      queryParams.append(key, value.toString());
    }
  });
  
  const response = await api.get(`/hosts/?${queryParams}`);
  return response.data;
};

export const getHost = async (hostId: number): Promise<Host> => {
  const response = await api.get(`/hosts/${hostId}`);
  return response.data;
};

export const getHostConflicts = async (hostId: number): Promise<HostConflict[]> => {
  try {
    const response = await api.get(`/hosts/${hostId}/conflicts`);
    return response.data;
  } catch (error) {
    console.warn('Host conflicts endpoint not available:', error);
    return [];
  }
};

export const getHostsByScan = async (scanId: number, state?: string): Promise<Host[]> => {
  const queryParams = state ? `?state=${state}` : '';
  const response = await api.get(`/hosts/scan/${scanId}${queryParams}`);
  return response.data;
};

export const getHostFilterData = async () => {
  const response = await api.get('/hosts/filters/data');
  return response.data;
};

// Dashboard API
export const getDashboardStats = async (): Promise<DashboardStats> => {
  const response = await api.get('/dashboard/stats');
  return response.data;
};

export const getPortStats = async () => {
  const response = await api.get('/dashboard/port-stats');
  return response.data;
};

export const getOsStats = async () => {
  const response = await api.get('/dashboard/os-stats');
  return response.data;
};

// Scopes API
export const getScopes = async (): Promise<ScopeSummary[]> => {
  const response = await api.get('/scopes/');
  return response.data;
};

export const getScope = async (scopeId: number, withFindingsOnly: boolean = false): Promise<Scope> => {
  const response = await api.get(`/scopes/${scopeId}?with_findings_only=${withFindingsOnly}`);
  return response.data;
};

export const createScope = async (name: string, description?: string): Promise<Scope> => {
  const response = await api.post('/scopes/', { name, description });
  return response.data;
};

export const deleteScope = async (scopeId: number) => {
  const response = await api.delete(`/scopes/${scopeId}`);
  return response.data;
};

export const uploadSubnetFile = async (
  file: File,
  scopeName: string,
  scopeDescription?: string
): Promise<SubnetFileUploadResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('scope_name', scopeName);
  if (scopeDescription) {
    formData.append('scope_description', scopeDescription);
  }
  
  const response = await api.post('/scopes/upload-subnets', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  
  return response.data;
};

export const getScopeHostMappings = async (scopeId: number): Promise<HostSubnetMapping[]> => {
  const response = await api.get(`/scopes/${scopeId}/host-mappings`);
  return response.data;
};

export const correlateAllHosts = async () => {
  const response = await api.post('/scopes/correlate-all');
  return response.data;
};

// Export API
export const exportScopeReport = async (scopeId: number, format: 'json' | 'csv' | 'html') => {
  const response = await api.get(`/export/scope/${scopeId}?format_type=${format}`, {
    responseType: 'blob'
  });
  
  // Create download
  const blob = new Blob([response.data]);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scope_report_${scopeId}_${new Date().toISOString().split('T')[0]}.${format}`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
  
  return response.data;
};

export const exportScanReport = async (scanId: number, format: 'json' | 'csv' | 'html') => {
  const response = await api.get(`/export/scan/${scanId}?format_type=${format}`, {
    responseType: 'blob'
  });
  
  // Create download
  const blob = new Blob([response.data]);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan_report_${scanId}_${new Date().toISOString().split('T')[0]}.${format}`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
  
  return response.data;
};

export const exportOutOfScopeReport = async (format: 'json' | 'csv' | 'html') => {
  const response = await api.get(`/export/out-of-scope?format_type=${format}`, {
    responseType: 'blob'
  });
  
  // Create download
  const blob = new Blob([response.data]);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `out_of_scope_report_${new Date().toISOString().split('T')[0]}.${format}`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
  
  return response.data;
};

// Get additional scan data
export const getOutOfScopeHosts = async (scanId?: number): Promise<OutOfScopeHost[]> => {
  const url = scanId ? `/scans/${scanId}/out-of-scope` : '/scans/out-of-scope';
  const response = await api.get(url);
  return response.data;
};

export const getEyewitnessResults = async (scanId: number): Promise<EyewitnessResult[]> => {
  const response = await api.get(`/scans/${scanId}/eyewitness`);
  return response.data;
};

export const getDNSRecords = async (hostname: string): Promise<DNSRecord[]> => {
  const response = await api.get(`/dns/records?hostname=${hostname}`);
  return response.data;
};

export interface CommandExplanation {
  has_command: boolean;
  tool: string;
  command?: string;
  target?: string;
  scan_type?: string;
  summary?: string;
  risk_assessment?: string;
  message?: string;
  arguments?: Array<{
    arg: string;
    description: string;
    category: string;
    risk_level: string;
    examples: string[];
  }>;
}

export const getScanCommandExplanation = async (scanId: number): Promise<CommandExplanation> => {
  const response = await api.get(`/scans/${scanId}/command-explanation`);
  return response.data;
};

// Parse Error API functions
export const getParseErrors = async (params: {
  skip?: number;
  limit?: number;
  status?: string;
} = {}): Promise<ParseErrorSummary[]> => {
  const queryParams = new URLSearchParams();
  
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined) {
      queryParams.append(key, value.toString());
    }
  });
  
  const response = await api.get(`/parse-errors/?${queryParams}`);
  return response.data;
};

export const getParseError = async (errorId: number): Promise<ParseError> => {
  const response = await api.get(`/parse-errors/${errorId}`);
  return response.data;
};

export const updateParseErrorStatus = async (errorId: number, status: string): Promise<{ message: string }> => {
  const response = await api.put(`/parse-errors/${errorId}/status?status=${status}`);
  return response.data;
};

export const deleteParseError = async (errorId: number): Promise<{ message: string }> => {
  const response = await api.delete(`/parse-errors/${errorId}`);
  return response.data;
};

export const getParseErrorStats = async (): Promise<{
  total_errors: number;
  unresolved: number;
  reviewed: number;
  fixed: number;
  ignored: number;
}> => {
  const response = await api.get('/parse-errors/stats/summary');
  return response.data;
};

// Reports API
export const generateHostsReport = async (
  format: 'csv' | 'html' | 'json',
  filters: {
    scan_id?: number;
    state?: string;
    search?: string;
    ports?: string;
    services?: string;
    port_states?: string;
    has_open_ports?: boolean;
    os_filter?: string;
  }
) => {
  const queryParams = new URLSearchParams();
  
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined) {
      queryParams.append(key, value.toString());
    }
  });
  
  const response = await api.get(`/reports/hosts/${format}?${queryParams}`, {
    responseType: 'blob'
  });
  
  // Create download
  const blob = new Blob([response.data]);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hosts_report_${new Date().toISOString().split('T')[0]}.${format}`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
  
  return response.data;
};

// Tool Ready Output API
export const getToolReadyOutput = async (
  format: string,
  filters: {
    search?: string;
    state?: string;
    ports?: string[];
    services?: string[];
    portStates?: string[];
    hasOpenPorts?: boolean;
    osFilter?: string;
    subnets?: string[];
    scanId?: number;
    includePorts?: boolean;
  }
): Promise<string> => {
  const params = new URLSearchParams();
  
  if (filters.search) params.append('search', filters.search);
  if (filters.state) params.append('state', filters.state);
  if (filters.ports?.length) params.append('ports', filters.ports.join(','));
  if (filters.services?.length) params.append('services', filters.services.join(','));
  if (filters.portStates?.length) params.append('port_states', filters.portStates.join(','));
  if (filters.hasOpenPorts !== undefined) params.append('has_open_ports', filters.hasOpenPorts.toString());
  if (filters.osFilter) params.append('os_filter', filters.osFilter);
  if (filters.subnets?.length) params.append('subnets', filters.subnets.join(','));
  if (filters.scanId) params.append('scan_id', filters.scanId.toString());
  if (filters.includePorts) params.append('include_ports', 'true');

  const response = await api.get(`/hosts/tool-ready/${format}?${params}`, {
    responseType: 'text'
  });
  
  return response.data;
};

export default api;
