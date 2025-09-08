import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface Scan {
  id: number;
  filename: string;
  scan_type: string | null;
  created_at: string;
  total_hosts: number;
  up_hosts: number;
  total_ports: number;
  open_ports: number;
}

export interface Host {
  id: number;
  scan_id: number;
  ip_address: string;
  hostname: string | null;
  state: string | null;
  os_name: string | null;
  ports: Port[];
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

export interface DashboardStats {
  total_scans: number;
  total_hosts: number;
  total_ports: number;
  total_subnets: number;
  recent_scans: Scan[];
  subnet_stats: SubnetStats[];
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

// Upload API
export const uploadFile = async (file: File, enrichDns: boolean = false) => {
  const formData = new FormData();
  formData.append('file', file);
  if (enrichDns) {
    formData.append('enrich_dns', 'true');
  }
  
  const response = await api.post('/upload/', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  
  return response.data;
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

export const getHostsByScan = async (scanId: number, state?: string): Promise<Host[]> => {
  const queryParams = state ? `?state=${state}` : '';
  const response = await api.get(`/hosts/scan/${scanId}${queryParams}`);
  return response.data;
};

export const getHostFilterData = async () => {
  const response = await api.get('/hosts/filters/ports');
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

export const getScope = async (scopeId: number): Promise<Scope> => {
  const response = await api.get(`/scopes/${scopeId}`);
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

export default api;