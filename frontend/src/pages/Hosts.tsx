import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
  CircularProgress,
  Alert,
  Badge,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkCheckIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';
import { getHosts, getHostFilterData } from '../services/api';
import type { Host } from '../services/api';
import HostFilters, { HostFilterOptions } from '../components/HostFilters';

export default function Hosts() {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<HostFilterOptions>({});
  const [filterData, setFilterData] = useState<any>(null);

  const fetchHosts = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params: any = {};
      
      // Convert filter options to API parameters
      if (filters.search) params.search = filters.search;
      if (filters.state) params.state = filters.state;
      if (filters.ports?.length) params.ports = filters.ports.join(',');
      if (filters.services?.length) params.services = filters.services.join(',');
      if (filters.portStates?.length) params.port_states = filters.portStates.join(',');
      if (filters.hasOpenPorts !== undefined) params.has_open_ports = filters.hasOpenPorts;
      if (filters.osFilter) params.os_filter = filters.osFilter;
      
      const data = await getHosts(params);
      setHosts(data);
    } catch (error) {
      console.error('Error fetching hosts:', error);
      setError('Failed to fetch hosts. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const fetchFilterData = async () => {
    try {
      const data = await getHostFilterData();
      setFilterData(data);
    } catch (error) {
      console.error('Error fetching filter data:', error);
    }
  };

  useEffect(() => {
    fetchFilterData();
  }, []);

  useEffect(() => {
    fetchHosts();
  }, [filters]);

  const handleFiltersChange = (newFilters: HostFilterOptions) => {
    setFilters(newFilters);
  };

  const getStateColor = (state: string | null) => {
    switch (state) {
      case 'up': return 'success';
      case 'down': return 'error';
      default: return 'default';
    }
  };

  const handleViewHost = (hostId: number) => {
    navigate(`/hosts/${hostId}`);
  };

  const getServiceIcon = (serviceName: string) => {
    const service = serviceName?.toLowerCase() || '';
    if (service.includes('http') || service.includes('web')) {
      return <NetworkCheckIcon />;
    }
    if (service.includes('ssh') || service.includes('ftp') || service.includes('telnet')) {
      return <SecurityIcon />;
    }
    if (service.includes('sql') || service.includes('database')) {
      return <StorageIcon />;
    }
    return <ComputerIcon />;
  };

  const getTopServices = (hostPorts: any[]) => {
    if (!hostPorts) return [];
    return hostPorts
      .filter(port => port.state === 'open' && port.service_name)
      .slice(0, 3)
      .map(port => port.service_name);
  };

  if (loading && !hosts.length) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">
          Discovered Hosts
        </Typography>
        <Badge badgeContent={hosts.length} color="primary" showZero>
          <ComputerIcon />
        </Badge>
      </Box>

      {/* Advanced Filters */}
      <HostFilters
        filters={filters}
        onFiltersChange={handleFiltersChange}
        availableData={filterData}
      />

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Box display="flex" justifyContent="center" alignItems="center" py={4}>
          <CircularProgress />
        </Box>
      ) : hosts.length === 0 ? (
        <Box textAlign="center" py={8}>
          <ComputerIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No hosts found
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Try adjusting your filters or upload more scan results
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {hosts.map((host) => {
            const openPorts = host.ports?.filter(port => port.state === 'open') || [];
            const topServices = getTopServices(host.ports || []);
            
            return (
              <Grid item xs={12} sm={6} md={4} key={host.id}>
                <Card sx={{ height: '100%', position: 'relative' }}>
                  <CardContent>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                      <Box display="flex" alignItems="center">
                        <ComputerIcon sx={{ mr: 1, color: 'primary.main' }} />
                        <Typography variant="h6" component="div" noWrap>
                          {host.ip_address}
                        </Typography>
                      </Box>
                      <Chip
                        label={host.state || 'unknown'}
                        color={getStateColor(host.state)}
                        size="small"
                      />
                    </Box>

                    {host.hostname && (
                      <Typography 
                        color="text.secondary" 
                        gutterBottom 
                        variant="body2" 
                        noWrap
                        title={host.hostname}
                      >
                        {host.hostname}
                      </Typography>
                    )}

                    {host.os_name && (
                      <Box display="flex" alignItems="center" mb={1}>
                        <Typography variant="body2" color="text.secondary" noWrap>
                          <strong>OS:</strong> {host.os_name}
                        </Typography>
                      </Box>
                    )}

                    <Box display="flex" gap={1} mb={2}>
                      <Badge badgeContent={openPorts.length} color="success">
                        <Chip
                          icon={<NetworkCheckIcon />}
                          label="Open"
                          size="small"
                          color="success"
                          variant="outlined"
                        />
                      </Badge>
                      <Badge badgeContent={host.ports?.length || 0} color="primary">
                        <Chip
                          icon={<ComputerIcon />}
                          label="Total"
                          size="small"
                          color="primary"
                          variant="outlined"
                        />
                      </Badge>
                    </Box>

                    {topServices.length > 0 && (
                      <Box mb={2}>
                        <Typography variant="caption" color="text.secondary" display="block" mb={1}>
                          Top Services:
                        </Typography>
                        <Box display="flex" gap={0.5} flexWrap="wrap">
                          {topServices.map((service, index) => (
                            <Chip
                              key={index}
                              icon={getServiceIcon(service)}
                              label={service}
                              size="small"
                              color="secondary"
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </Box>
                    )}

                    <Button
                      fullWidth
                      variant="outlined"
                      onClick={() => handleViewHost(host.id)}
                      sx={{ mt: 'auto' }}
                    >
                      View Details
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}
    </Box>
  );
}