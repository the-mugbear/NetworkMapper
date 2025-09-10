import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Paper,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Tab,
  Card,
  CardContent,
  IconButton,
  Link,
  Tooltip,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Computer as HostIcon,
  Security as PortIcon,
  Terminal as TerminalIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import { getScan, getHostsByScan } from '../services/api';
import type { Host } from '../services/api';
import CommandExplanation from '../components/CommandExplanation';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<any>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [tabValue, setTabValue] = useState(0);

  useEffect(() => {
    const fetchData = async () => {
      if (!scanId) return;

      try {
        const [scanData, hostsData] = await Promise.all([
          getScan(parseInt(scanId)),
          getHostsByScan(parseInt(scanId))
        ]);
        
        setScan(scanData);
        setHosts(hostsData);
      } catch (error) {
        console.error('Error fetching scan details:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [scanId]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const getHostStateColor = (state: string | null) => {
    switch (state) {
      case 'up': return 'success';
      case 'down': return 'error';
      default: return 'default';
    }
  };

  const getPortStateColor = (state: string | null) => {
    switch (state) {
      case 'open': return 'success';
      case 'closed': return 'error';
      case 'filtered': return 'warning';
      default: return 'default';
    }
  };

  const isWebPort = (portNumber: number): boolean => {
    return portNumber === 80 || portNumber === 443;
  };

  const getWebUrl = (ipAddress: string, portNumber: number): string => {
    const protocol = portNumber === 443 ? 'https' : 'http';
    const port = (portNumber === 80 || portNumber === 443) ? '' : `:${portNumber}`;
    return `${protocol}://${ipAddress}${port}`;
  };

  const handleWebLinkClick = (url: string) => {
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading scan details...</Typography>
      </Box>
    );
  }

  if (!scan) {
    return (
      <Box textAlign="center" py={8}>
        <Typography variant="h6" color="error">
          Scan not found
        </Typography>
        <Button onClick={() => navigate('/scans')} sx={{ mt: 2 }}>
          Back to Scans
        </Button>
      </Box>
    );
  }

  const upHosts = hosts.filter(host => host.state === 'up').length;
  const totalPorts = hosts.reduce((acc, host) => acc + host.ports.length, 0);
  const openPorts = hosts.reduce((acc, host) => 
    acc + host.ports.filter(port => port.state === 'open').length, 0
  );

  return (
    <Box>
      <Box display="flex" alignItems="center" mb={3}>
        <Button
          startIcon={<BackIcon />}
          onClick={() => navigate('/scans')}
          sx={{ mr: 2 }}
        >
          Back to Scans
        </Button>
        <Typography variant="h4">
          {scan.filename}
        </Typography>
      </Box>

      {/* Scan Overview */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Hosts Up
              </Typography>
              <Typography variant="h4">
                {upHosts}/{hosts.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Open Ports
              </Typography>
              <Typography variant="h4">
                {openPorts}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Ports
              </Typography>
              <Typography variant="h4">
                {totalPorts}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Scan Date
              </Typography>
              <Typography variant="h6">
                {new Date(scan.created_at).toLocaleDateString()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="Hosts" icon={<HostIcon />} />
            <Tab label="All Ports" icon={<PortIcon />} />
            <Tab label="Command" icon={<TerminalIcon />} />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell>Hostname</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>OS</TableCell>
                  <TableCell>Open Ports</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {hosts.map((host) => (
                  <TableRow key={host.id} hover>
                    <TableCell>{host.ip_address}</TableCell>
                    <TableCell>{host.hostname || 'N/A'}</TableCell>
                    <TableCell>
                      <Chip
                        label={host.state || 'unknown'}
                        color={getHostStateColor(host.state)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{host.os_name || 'Unknown'}</TableCell>
                    <TableCell>
                      <Box display="flex" alignItems="center" gap={1}>
                        <span>{host.ports.filter(port => port.state === 'open').length}</span>
                        {host.ports.filter(port => port.state === 'open' && isWebPort(port.port_number)).map(port => (
                          <Tooltip key={port.id} title={`Open ${getWebUrl(host.ip_address, port.port_number)}`}>
                            <IconButton
                              size="small"
                              onClick={() => handleWebLinkClick(getWebUrl(host.ip_address, port.port_number))}
                              sx={{ color: 'primary.main' }}
                            >
                              <OpenInNewIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        ))}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Host</TableCell>
                  <TableCell>Port</TableCell>
                  <TableCell>Protocol</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Service</TableCell>
                  <TableCell>Version</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {hosts.flatMap(host => 
                  host.ports.map(port => (
                    <TableRow key={`${host.id}-${port.id}`} hover>
                      <TableCell>{host.ip_address}</TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <span>{port.port_number}</span>
                          {port.state === 'open' && isWebPort(port.port_number) && (
                            <Tooltip title={`Open ${getWebUrl(host.ip_address, port.port_number)}`}>
                              <IconButton
                                size="small"
                                onClick={() => handleWebLinkClick(getWebUrl(host.ip_address, port.port_number))}
                                sx={{ color: 'primary.main' }}
                              >
                                <OpenInNewIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>{port.protocol}</TableCell>
                      <TableCell>
                        <Chip
                          label={port.state || 'unknown'}
                          color={getPortStateColor(port.state)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>{port.service_name || 'Unknown'}</TableCell>
                      <TableCell>
                        {port.service_product && port.service_version
                          ? `${port.service_product} ${port.service_version}`
                          : port.service_product || 'N/A'
                        }
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <CommandExplanation scanId={parseInt(scanId!)} />
        </TabPanel>
      </Paper>
    </Box>
  );
}