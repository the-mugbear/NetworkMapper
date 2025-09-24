import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
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
  Tooltip,
  Menu,
  MenuItem,
  Stack,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkCheckIcon,
  Storage as StorageIcon,
  FileDownload as FileDownloadIcon,
  Code as CodeIcon,
  BookmarkAdded as BookmarkIcon,
  BookmarkBorder as BookmarkBorderIcon,
  Note as NoteIcon,
} from '@mui/icons-material';
import { getHosts, getHostFilterData, followHost, unfollowHost } from '../services/api';
import type { Host, FollowStatus, HostFollowInfo } from '../services/api';
import HostFilters, { HostFilterOptions } from '../components/HostFilters';
import ReportsDialog from '../components/ReportsDialog';
import ToolReadyOutput from '../components/ToolReadyOutput';
import { PORTS_OF_INTEREST_SET, PORTS_OF_INTEREST } from '../utils/portsOfInterest';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';

interface HostPort {
  state: string;
  service_name?: string;
  port: number;
  protocol: string;
}

const FOLLOW_STATUS_OPTIONS: Array<{
  value: FollowStatus;
  label: string;
  color: 'info' | 'warning' | 'success';
}> = [
  { value: 'watching', label: 'Watching', color: 'info' },
  { value: 'in_review', label: 'In Review', color: 'warning' },
  { value: 'reviewed', label: 'Reviewed', color: 'success' },
];

export default function Hosts() {
  const navigate = useNavigate();
  const location = useLocation();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<HostFilterOptions>({});
  const [filterData, setFilterData] = useState<any>(null);
  const [reportsDialogOpen, setReportsDialogOpen] = useState(false);
  const [toolReadyDialogOpen, setToolReadyDialogOpen] = useState(false);
  const [followMenu, setFollowMenu] = useState<{ hostId: number; anchorEl: HTMLElement } | null>(null);
  const [updatingHostId, setUpdatingHostId] = useState<number | null>(null);
  const [followFilter, setFollowFilter] = useState<'all' | FollowStatus>('all');
  const [onlyWithNotes, setOnlyWithNotes] = useState(false);

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
      if (filters.subnets?.length) params.subnets = filters.subnets.join(',');
      if (filters.hasCriticalVulns !== undefined) params.has_critical_vulns = filters.hasCriticalVulns;
      if (filters.hasHighVulns !== undefined) params.has_high_vulns = filters.hasHighVulns;
      if (filters.minRiskScore !== undefined) params.min_risk_score = filters.minRiskScore;
      
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
    // Parse URL parameters on component mount
    const urlParams = new URLSearchParams(location.search);
    const initialFilters: HostFilterOptions = {};
    
    // Handle subnet filter from URL
    const subnetsParam = urlParams.get('subnets');
    if (subnetsParam) {
      initialFilters.subnets = [decodeURIComponent(subnetsParam)];
    }
    
    if (Object.keys(initialFilters).length > 0) {
      setFilters(initialFilters);
    }
  }, [location.search]);

  useEffect(() => {
    fetchHosts();
    // Refresh filter data when filters change to ensure latest data
    fetchFilterData();
  }, [filters]);

  // Refresh filter data when page becomes visible (e.g., after uploading scans)
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        fetchFilterData();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, []);

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

  const getTopServices = (hostPorts: HostPort[]) => {
    if (!hostPorts) return [];
    return hostPorts
      .filter(port => port.state === 'open' && port.service_name)
      .slice(0, 3)
      .map(port => port.service_name);
  };

  const handleFollowMenuOpen = (event: React.MouseEvent<HTMLElement>, hostId: number) => {
    setFollowMenu({ hostId, anchorEl: event.currentTarget });
  };

  const handleFollowMenuClose = () => {
    setFollowMenu(null);
  };

  const applyFollowUpdate = (hostId: number, followInfo: HostFollowInfo | null) => {
    setHosts(previous =>
      previous.map((host) =>
        host.id === hostId
          ? { ...host, follow: followInfo }
          : host
      )
    );
  };

  const handleFollowChange = async (hostId: number, status: FollowStatus | 'none') => {
    setUpdatingHostId(hostId);
    try {
      if (status === 'none') {
        await unfollowHost(hostId);
        applyFollowUpdate(hostId, null);
      } else {
        const response = await followHost(hostId, status);
        applyFollowUpdate(hostId, response);
      }
      setError(null);
    } catch (err) {
      console.error('Error updating follow status:', err);
      setError('Unable to update follow status. Please try again.');
    } finally {
      setUpdatingHostId(null);
      handleFollowMenuClose();
    }
  };

  const filteredHosts = hosts.filter((host) => {
    const noteCount = host.note_count ?? host.notes?.length ?? 0;

    if (followFilter !== 'all' && host.follow?.status !== followFilter) {
      return false;
    }

    if (onlyWithNotes && noteCount === 0) {
      return false;
    }

    return true;
  });

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
        <Box display="flex" alignItems="center" gap={2}>
          <Button
            variant="contained"
            startIcon={<CodeIcon />}
            onClick={() => setToolReadyDialogOpen(true)}
            disabled={loading || filteredHosts.length === 0}
          >
            Tool Ready Output
          </Button>
          <Button
            variant="outlined"
            startIcon={<FileDownloadIcon />}
            onClick={() => setReportsDialogOpen(true)}
            disabled={loading || filteredHosts.length === 0}
          >
            Export Report
          </Button>
          <Badge badgeContent={filteredHosts.length} color="primary" showZero>
            <ComputerIcon />
          </Badge>
        </Box>
      </Box>

      {/* Advanced Filters */}
      <HostFilters
        filters={filters}
        onFiltersChange={handleFiltersChange}
        availableData={filterData}
      />

      <Box display="flex" flexWrap="wrap" alignItems="center" justifyContent="space-between" gap={2} mb={3}>
        <Stack direction="row" spacing={1} flexWrap="wrap" alignItems="center">
          <Typography variant="body2" color="text.secondary">
            Follow status:
          </Typography>
          <Chip
            label="All"
            size="small"
            color={followFilter === 'all' ? 'primary' : 'default'}
            variant={followFilter === 'all' ? 'filled' : 'outlined'}
            onClick={() => setFollowFilter('all')}
          />
          {FOLLOW_STATUS_OPTIONS.map((option) => (
            <Chip
              key={option.value}
              label={option.label}
              size="small"
              color={followFilter === option.value ? option.color : 'default'}
              variant={followFilter === option.value ? 'filled' : 'outlined'}
              onClick={() => setFollowFilter(option.value)}
            />
          ))}
        </Stack>
        <FormControlLabel
          control={
            <Switch
              checked={onlyWithNotes}
              onChange={(event) => setOnlyWithNotes(event.target.checked)}
            />
          }
          label="Only hosts with notes"
        />
      </Box>

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
      ) : filteredHosts.length === 0 ? (
        <Box textAlign="center" py={8}>
          <ComputerIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No hosts match current filters
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Clear the follow or notes filters, or adjust the advanced filters above.
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {filteredHosts.map((host) => {
            const openPorts = host.ports?.filter(port => port.state === 'open') || [];
            const topServices = getTopServices(host.ports || []);
            const portsOfInterest = openPorts.filter((port) => PORTS_OF_INTEREST_SET.has(port.port_number));
            const hasCritical = host.vulnerability_summary?.critical && host.vulnerability_summary.critical > 0;
            const noteCount = host.note_count ?? host.notes?.length ?? 0;
            const latestNote = host.notes && host.notes.length > 0 ? host.notes[0] : undefined;
            const latestNotePreview = latestNote?.body
              ? `${latestNote.body.slice(0, 160)}${latestNote.body.length > 160 ? '…' : ''}`
              : null;
            const followStatus = host.follow?.status ?? null;
            const followOption = followStatus
              ? FOLLOW_STATUS_OPTIONS.find(option => option.value === followStatus) ?? null
              : null;
            const followLabel = followOption?.label ?? 'Follow';
            const followChipColor = followOption?.color ?? 'default';
            
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
                      <Stack direction="row" gap={1} alignItems="center">
                        <Tooltip
                          title={noteCount > 0 ? (
                            <Box>
                              <Typography variant="caption" display="block">
                                {`${noteCount} note${noteCount === 1 ? '' : 's'} added`}
                              </Typography>
                              {latestNotePreview && (
                                <Typography variant="caption" color="text.secondary">
                                  “{latestNotePreview}”
                                </Typography>
                              )}
                            </Box>
                          ) : 'No notes yet'}
                        >
                          <Chip
                            icon={<NoteIcon />}
                            label={`${noteCount}`}
                            size="small"
                            color={noteCount > 0 ? 'secondary' : 'default'}
                            variant={noteCount > 0 ? 'filled' : 'outlined'}
                          />
                        </Tooltip>
                        <Tooltip title="Update follow status">
                          <Chip
                            icon={followStatus ? <BookmarkIcon /> : <BookmarkBorderIcon />}
                            label={followLabel}
                            color={followChipColor}
                            size="small"
                            clickable
                            onClick={(event) => handleFollowMenuOpen(event, host.id)}
                            disabled={updatingHostId === host.id}
                            variant={followStatus ? 'filled' : 'outlined'}
                          />
                        </Tooltip>
                        {portsOfInterest.length > 0 && (
                          <Tooltip
                            title={
                              <Box>
                                {portsOfInterest.map((port) => {
                                  const definition = PORTS_OF_INTEREST.find((entry) => entry.port === port.port_number);
                                  return (
                                    <Typography variant="caption" key={`${host.id}-poi-${port.port_number}`} display="block">
                                      {port.port_number}/{port.service_name || 'unknown'} – {definition?.label || 'High-value port'}
                                    </Typography>
                                  );
                                })}
                              </Box>
                            }
                            arrow
                          >
                            <Chip label="Ports of interest" color="warning" size="small" />
                          </Tooltip>
                        )}
                        {hasCritical && (
                          <Chip label="Critical vulns" color="error" size="small" />
                        )}
                          <Chip
                            label={host.state || 'unknown'}
                            color={getStateColor(host.state)}
                            size="small"
                          />
                      </Stack>
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

                    {latestNotePreview && (
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        “{latestNotePreview}”
                      </Typography>
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

                    {/* Vulnerability Information */}
                    {host.vulnerability_summary && host.vulnerability_summary.total_vulnerabilities > 0 && (
                      <Box mb={2}>
                        <Typography variant="caption" color="text.secondary" display="block" mb={1}>
                          Vulnerabilities:
                        </Typography>
                        <Box display="flex" gap={0.5} flexWrap="wrap">
                          {host.vulnerability_summary.critical > 0 && (
                            <Chip
                              label={`${host.vulnerability_summary.critical} Critical`}
                              size="small"
                              sx={{ backgroundColor: '#d32f2f', color: 'white' }}
                            />
                          )}
                          {host.vulnerability_summary.high > 0 && (
                            <Chip
                              label={`${host.vulnerability_summary.high} High`}
                              size="small"
                              sx={{ backgroundColor: '#f57c00', color: 'white' }}
                            />
                          )}
                          {host.vulnerability_summary.medium > 0 && (
                            <Chip
                              label={`${host.vulnerability_summary.medium} Medium`}
                              size="small"
                              sx={{ backgroundColor: '#ffa000', color: 'white' }}
                            />
                          )}
                          {host.vulnerability_summary.low > 0 && (
                            <Chip
                              label={`${host.vulnerability_summary.low} Low`}
                              size="small"
                              sx={{ backgroundColor: '#388e3c', color: 'white' }}
                            />
                          )}
                          {host.vulnerability_summary.info > 0 && (
                            <Chip
                              label={`${host.vulnerability_summary.info} Info`}
                              size="small"
                              color="primary"
                            />
                          )}
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

      <Menu
        anchorEl={followMenu?.anchorEl ?? null}
        open={Boolean(followMenu)}
        onClose={handleFollowMenuClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {followMenu && FOLLOW_STATUS_OPTIONS.map((option) => (
          <MenuItem
            key={option.value}
            selected={hosts.find(host => host.id === followMenu.hostId)?.follow?.status === option.value}
            onClick={() => handleFollowChange(followMenu.hostId, option.value)}
            disabled={updatingHostId === followMenu.hostId}
          >
            {option.label}
          </MenuItem>
        ))}
        {followMenu && (
          <MenuItem
            onClick={() => handleFollowChange(followMenu.hostId, 'none')}
            disabled={updatingHostId === followMenu.hostId || !hosts.find(host => host.id === followMenu.hostId)?.follow}
          >
            Stop Following
          </MenuItem>
        )}
      </Menu>

      {/* Reports Dialog */}
      <ReportsDialog
        open={reportsDialogOpen}
        onClose={() => setReportsDialogOpen(false)}
        filters={filters}
        totalHosts={filteredHosts.length}
      />

      {/* Tool Ready Output Dialog */}
      <ToolReadyOutput
        open={toolReadyDialogOpen}
        onClose={() => setToolReadyDialogOpen(false)}
        filters={filters}
      />
    </Box>
  );
}
