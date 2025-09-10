import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  Autocomplete,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  Grid,
  FormControlLabel,
  Switch,
  Divider,
  Alert,
  Badge,
  Tooltip,
  IconButton,
  Paper,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Clear as ClearIcon,
  FilterList as FilterListIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  NetworkCheck as NetworkCheckIcon,
  Search as SearchIcon,
  BookmarkBorder as BookmarkIcon,
  Star as StarIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';

export interface HostFilterOptions {
  search?: string;
  state?: string;
  ports?: string[];
  services?: string[];
  portStates?: string[];
  hasOpenPorts?: boolean;
  osFilter?: string;
  subnets?: string[];
}

export interface HostFiltersProps {
  filters: HostFilterOptions;
  onFiltersChange: (filters: HostFilterOptions) => void;
  availableData?: {
    common_ports: Array<{ port: number; service: string; state: string; count: number }>;
    services: Array<{ name: string; count: number }>;
    operating_systems: Array<{ name: string; count: number }>;
    subnets: Array<{ cidr: string; scope_name: string; host_count: number }>;
  };
}

// Predefined filter shortcuts
const COMMON_FILTER_PRESETS = [
  {
    name: 'Web Servers',
    icon: <NetworkCheckIcon />,
    description: 'Hosts with web services (HTTP/HTTPS)',
    filters: { services: ['http', 'https'], portStates: ['open'] }
  },
  {
    name: 'SSH Servers',
    icon: <SecurityIcon />,
    description: 'Hosts with SSH access',
    filters: { ports: ['22'], portStates: ['open'] }
  },
  {
    name: 'Database Servers',
    icon: <ComputerIcon />,
    description: 'Common database ports',
    filters: { ports: ['3306', '5432', '1433', '27017'], portStates: ['open'] }
  },
  {
    name: 'Windows Hosts',
    icon: <ComputerIcon />,
    description: 'Windows-specific services',
    filters: { ports: ['135', '139', '445'], portStates: ['open'] }
  },
  {
    name: 'High Risk Ports',
    icon: <SecurityIcon />,
    description: 'Potentially high-risk open ports',
    filters: { ports: ['21', '23', '135', '139', '445', '1433', '3389'], portStates: ['open'] }
  }
];

const SERVICE_SEARCH_PRESETS = [
  {
    name: 'SSH',
    icon: <SecurityIcon />,
    description: 'Search for SSH services',
    searchTerm: 'ssh'
  },
  {
    name: 'HTTP/Web',
    icon: <NetworkCheckIcon />,
    description: 'Search for web services',
    searchTerm: 'http'
  },
  {
    name: 'SNMP',
    icon: <NetworkCheckIcon />,
    description: 'Search for SNMP services',
    searchTerm: 'snmp'
  },
  {
    name: 'RDP',
    icon: <ComputerIcon />,
    description: 'Search for Remote Desktop',
    searchTerm: 'rdp'
  },
  {
    name: 'FTP',
    icon: <StorageIcon />,
    description: 'Search for FTP services',
    searchTerm: 'ftp'
  },
  {
    name: 'MySQL',
    icon: <StorageIcon />,
    description: 'Search for MySQL databases',
    searchTerm: 'mysql'
  }
];

const PORT_STATE_OPTIONS = [
  { value: 'open', label: 'Open', color: 'success' },
  { value: 'closed', label: 'Closed', color: 'default' },
  { value: 'filtered', label: 'Filtered', color: 'warning' }
];

const HOST_STATE_OPTIONS = [
  { value: '', label: 'All States' },
  { value: 'up', label: 'Up' },
  { value: 'down', label: 'Down' }
];

const HostFilters: React.FC<HostFiltersProps> = ({ 
  filters, 
  onFiltersChange, 
  availableData 
}) => {
  const [expanded, setExpanded] = useState(false);
  const [activeFiltersCount, setActiveFiltersCount] = useState(0);

  // Update active filters count
  useEffect(() => {
    const count = [
      filters.search,
      filters.state,
      filters.ports?.length,
      filters.services?.length,
      filters.portStates?.length,
      filters.hasOpenPorts !== undefined,
      filters.osFilter
    ].filter(Boolean).length;
    
    setActiveFiltersCount(count);
  }, [filters]);

  const handleFilterChange = (key: keyof HostFilterOptions, value: any) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  const handleClearFilters = () => {
    onFiltersChange({});
  };

  const applyPreset = (preset: typeof COMMON_FILTER_PRESETS[0]) => {
    onFiltersChange({ ...filters, ...preset.filters });
  };

  const applyServiceSearch = (preset: typeof SERVICE_SEARCH_PRESETS[0]) => {
    onFiltersChange({ ...filters, search: preset.searchTerm });
  };

  const getPortOptions = () => {
    if (!availableData?.common_ports) return [];
    
    // Group by port number and get the most common service name
    const portMap = new Map<number, { service: string; count: number }>();
    
    availableData.common_ports.forEach(port => {
      if (!portMap.has(port.port) || portMap.get(port.port)!.count < port.count) {
        portMap.set(port.port, { service: port.service, count: port.count });
      }
    });
    
    return Array.from(portMap.entries())
      .map(([port, data]) => ({
        label: `${port} (${data.service})`,
        value: port.toString(),
        count: data.count
      }))
      .sort((a, b) => b.count - a.count);
  };

  const getServiceOptions = () => {
    return availableData?.services?.map(service => ({
      label: `${service.name} (${service.count} hosts)`,
      value: service.name,
      count: service.count
    })) || [];
  };

  const getOsOptions = () => {
    return availableData?.operating_systems?.map(os => ({
      label: `${os.name} (${os.count} hosts)`,
      value: os.name,
      count: os.count
    })) || [];
  };

  const getSubnetOptions = () => {
    return availableData?.subnets?.map(subnet => ({
      label: `${subnet.cidr} - ${subnet.scope_name} (${subnet.host_count} hosts)`,
      value: subnet.cidr,
      scope_name: subnet.scope_name,
      count: subnet.host_count
    })) || [];
  };

  return (
    <Paper elevation={2} sx={{ mb: 3 }}>
      <Box p={2}>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <Badge badgeContent={activeFiltersCount} color="primary">
              <FilterListIcon />
            </Badge>
            <Typography variant="h6">Host Filters</Typography>
            {activeFiltersCount > 0 && (
              <Tooltip title="Clear all filters">
                <IconButton size="small" onClick={handleClearFilters}>
                  <ClearIcon />
                </IconButton>
              </Tooltip>
            )}
          </Box>
          <Button
            variant="text"
            onClick={() => setExpanded(!expanded)}
            endIcon={<ExpandMoreIcon sx={{ transform: expanded ? 'rotate(180deg)' : 'none' }} />}
          >
            {expanded ? 'Show Less' : 'Show More'}
          </Button>
        </Box>

        {/* Quick Search */}
        <TextField
          fullWidth
          label="Search hosts"
          placeholder="Enter IP, hostname, OS, port number, or service name (ssh, http, snmp, etc.)"
          value={filters.search || ''}
          onChange={(e) => handleFilterChange('search', e.target.value)}
          InputProps={{
            startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />,
          }}
          helperText="Try: ssh, http, snmp, rdp, ftp, smtp, mysql, web, 22, 80, 443"
          sx={{ mb: 2 }}
        />

        {/* Filter Presets */}
        <Box mb={2}>
          <Typography variant="subtitle2" gutterBottom>
            Quick Filters
          </Typography>
          <Box display="flex" gap={1} flexWrap="wrap" mb={1}>
            {COMMON_FILTER_PRESETS.map((preset, index) => (
              <Tooltip key={index} title={preset.description}>
                <Chip
                  icon={preset.icon}
                  label={preset.name}
                  onClick={() => applyPreset(preset)}
                  variant="outlined"
                  size="small"
                  clickable
                />
              </Tooltip>
            ))}
          </Box>
          
          <Typography variant="subtitle2" gutterBottom sx={{ mt: 1 }}>
            Service Search
          </Typography>
          <Box display="flex" gap={1} flexWrap="wrap">
            {SERVICE_SEARCH_PRESETS.map((preset, index) => (
              <Tooltip key={`service-${index}`} title={preset.description}>
                <Chip
                  icon={preset.icon}
                  label={preset.name}
                  onClick={() => applyServiceSearch(preset)}
                  variant="outlined"
                  size="small"
                  clickable
                  color="secondary"
                />
              </Tooltip>
            ))}
          </Box>
        </Box>

        {expanded && (
          <Box>
            <Divider sx={{ my: 2 }} />
            
            <Grid container spacing={3}>
              {/* Host State Filter */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Host State</InputLabel>
                  <Select
                    value={filters.state || ''}
                    label="Host State"
                    onChange={(e) => handleFilterChange('state', e.target.value || undefined)}
                  >
                    {HOST_STATE_OPTIONS.map(option => (
                      <MenuItem key={option?.value} value={option?.value}>
                        {option?.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {/* Open Ports Toggle */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={filters.hasOpenPorts || false}
                      onChange={(e) => handleFilterChange('hasOpenPorts', e.target.checked || undefined)}
                    />
                  }
                  label="Has Open Ports"
                />
              </Grid>

              {/* Operating System Filter */}
              <Grid item xs={12} sm={6} md={6}>
                <Autocomplete
                  size="small"
                  options={getOsOptions()}
                  value={getOsOptions().find(o => o.value === filters.osFilter) || null}
                  onChange={(_, value) => handleFilterChange('osFilter', value?.value)}
                  getOptionLabel={(option) => option?.label || ''}
                  renderInput={(params) => (
                    <TextField {...params} label="Operating System" />
                  )}
                  renderOption={(props, option) => (
                    <li {...props}>
                      <Box display="flex" alignItems="center" width="100%">
                        <ComputerIcon sx={{ mr: 1 }} />
                        <Box>
                          <Typography>{option?.value}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {option?.count} hosts
                          </Typography>
                        </Box>
                      </Box>
                    </li>
                  )}
                />
              </Grid>

              {/* Port Numbers Filter */}
              <Grid item xs={12} md={6}>
                <Autocomplete
                  multiple
                  size="small"
                  options={getPortOptions()}
                  value={filters.ports?.map(p => getPortOptions().find(o => o.value === p)).filter(Boolean) || []}
                  onChange={(_, values) => handleFilterChange('ports', values.map(v => v?.value))}
                  getOptionLabel={(option) => option?.label || ''}
                  renderTags={(tagValue, getTagProps) =>
                    tagValue.filter(Boolean).map((option, index) => (
                      <Chip
                        {...getTagProps({ index })}
                        key={option?.value}
                        label={option?.label}
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField {...params} label="Ports" placeholder="Select ports..." />
                  )}
                  renderOption={(props, option) => (
                    <li {...props}>
                      <Box display="flex" alignItems="center" width="100%">
                        <NetworkCheckIcon sx={{ mr: 1 }} />
                        <Box>
                          <Typography>{option?.label}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {option?.count} instances
                          </Typography>
                        </Box>
                      </Box>
                    </li>
                  )}
                />
              </Grid>

              {/* Services Filter */}
              <Grid item xs={12} md={6}>
                <Autocomplete
                  multiple
                  size="small"
                  options={getServiceOptions()}
                  value={filters.services?.map(s => getServiceOptions().find(o => o.value === s)).filter(Boolean) || []}
                  onChange={(_, values) => handleFilterChange('services', values.map(v => v?.value))}
                  getOptionLabel={(option) => option?.label || ''}
                  renderTags={(tagValue, getTagProps) =>
                    tagValue.filter(Boolean).map((option, index) => (
                      <Chip
                        {...getTagProps({ index })}
                        key={option?.value}
                        label={option?.value}
                        size="small"
                        color="secondary"
                        variant="outlined"
                      />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField {...params} label="Services" placeholder="Select services..." />
                  )}
                  renderOption={(props, option) => (
                    <li {...props}>
                      <Box display="flex" alignItems="center" width="100%">
                        <SecurityIcon sx={{ mr: 1 }} />
                        <Box>
                          <Typography>{option?.value}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {option?.count} hosts
                          </Typography>
                        </Box>
                      </Box>
                    </li>
                  )}
                />
              </Grid>

              {/* Port States Filter */}
              <Grid item xs={12} md={6}>
                <Autocomplete
                  multiple
                  size="small"
                  options={PORT_STATE_OPTIONS}
                  value={filters.portStates?.map(s => PORT_STATE_OPTIONS.find(o => o.value === s)).filter(Boolean) || []}
                  onChange={(_, values) => handleFilterChange('portStates', values.map(v => v?.value))}
                  getOptionLabel={(option) => option?.label || ''}
                  renderTags={(tagValue, getTagProps) =>
                    tagValue.filter(Boolean).map((option, index) => (
                      <Chip
                        {...getTagProps({ index })}
                        key={option?.value}
                        label={option?.label}
                        size="small"
                        color={option?.color as any}
                        variant="outlined"
                      />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField {...params} label="Port States" placeholder="Select port states..." />
                  )}
                />
              </Grid>

              {/* Subnets Filter */}
              <Grid item xs={12} md={6}>
                <Autocomplete
                  multiple
                  size="small"
                  options={getSubnetOptions()}
                  value={filters.subnets?.map(s => getSubnetOptions().find(o => o.value === s)).filter(Boolean) || []}
                  onChange={(_, values) => handleFilterChange('subnets', values.map(v => v?.value))}
                  getOptionLabel={(option) => option?.label || ''}
                  renderTags={(tagValue, getTagProps) =>
                    tagValue.filter(Boolean).map((option, index) => (
                      <Chip
                        {...getTagProps({ index })}
                        key={option?.value}
                        label={`${option?.value} (${option?.scope_name})`}
                        size="small"
                        color="info"
                        variant="outlined"
                      />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField {...params} label="Subnets" placeholder="Select subnets..." />
                  )}
                  renderOption={(props, option) => (
                    <li {...props}>
                      <Box display="flex" alignItems="center" width="100%">
                        <NetworkCheckIcon sx={{ mr: 1 }} />
                        <Box>
                          <Typography>{option?.value}</Typography>
                          <Typography variant="body2" color="primary">
                            {option?.scope_name}
                          </Typography>
                          <Typography variant="caption" color="textSecondary">
                            {option?.count} hosts
                          </Typography>
                        </Box>
                      </Box>
                    </li>
                  )}
                />
              </Grid>
            </Grid>

            {activeFiltersCount > 0 && (
              <Box mt={2}>
                <Alert severity="info" sx={{ display: 'flex', alignItems: 'center' }}>
                  <Typography variant="body2">
                    {activeFiltersCount} filter{activeFiltersCount !== 1 ? 's' : ''} active
                  </Typography>
                  <Button
                    size="small"
                    onClick={handleClearFilters}
                    sx={{ ml: 'auto' }}
                  >
                    Clear All
                  </Button>
                </Alert>
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default HostFilters;