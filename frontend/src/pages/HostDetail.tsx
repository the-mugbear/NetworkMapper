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
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  IconButton,
  Alert,
  Badge,
  Divider,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  ExpandMore as ExpandMoreIcon,
  Computer as ComputerIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Timeline as TimelineIcon,
  Visibility as VisibilityIcon,
} from '@mui/icons-material';
import { getHost, getHostConflicts } from '../services/api';
import type { Host, HostConflict } from '../services/api';
import HostRiskAnalysis from '../components/HostRiskAnalysis';

export default function HostDetail() {
  const { hostId } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const [host, setHost] = useState<Host | null>(null);
  const [conflicts, setConflicts] = useState<HostConflict[]>([]);
  const [showConflicts, setShowConflicts] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHost = async () => {
      if (!hostId) return;

      try {
        const [hostData, conflictData] = await Promise.all([
          getHost(parseInt(hostId)),
          getHostConflicts(parseInt(hostId))
        ]);
        setHost(hostData);
        setConflicts(conflictData || []);
      } catch (error) {
        console.error('Error fetching host details:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchHost();
  }, [hostId]);

  const getStateColor = (state: string | null) => {
    switch (state) {
      case 'up': return 'success';
      case 'down': return 'error';
      case 'open': return 'success';
      case 'closed': return 'error';
      case 'filtered': return 'warning';
      default: return 'default';
    }
  };

  const getConfidenceColor = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 70) return 'warning';
    return 'error';
  };

  const formatConfidenceTooltip = (conflict: HostConflict) => {
    return `Confidence: ${conflict.confidence_score}% | Source: ${conflict.scan_type} | Method: ${conflict.method}`;
  };

  const hasConflicts = conflicts.length > 0;
  const conflictsByField = conflicts.reduce((acc, conflict) => {
    if (!acc[conflict.field_name]) acc[conflict.field_name] = [];
    acc[conflict.field_name].push(conflict);
    return acc;
  }, {} as Record<string, HostConflict[]>);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading host details...</Typography>
      </Box>
    );
  }

  if (!host) {
    return (
      <Box textAlign="center" py={8}>
        <Typography variant="h6" color="error">
          Host not found
        </Typography>
        <Button onClick={() => navigate('/hosts')} sx={{ mt: 2 }}>
          Back to Hosts
        </Button>
      </Box>
    );
  }

  const openPorts = host.ports.filter(port => port.state === 'open');
  const closedPorts = host.ports.filter(port => port.state === 'closed');
  const filteredPorts = host.ports.filter(port => port.state === 'filtered');

  return (
    <Box>
      <Box display="flex" alignItems="center" justifyContent="space-between" mb={3}>
        <Box display="flex" alignItems="center">
          <Button
            startIcon={<BackIcon />}
            onClick={() => navigate('/hosts')}
            sx={{ mr: 2 }}
          >
            Back to Hosts
          </Button>
          <ComputerIcon sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h4">
            {host.ip_address}
          </Typography>
          {hasConflicts && (
            <Tooltip title={`${conflicts.length} data conflicts detected`}>
              <Badge badgeContent={conflicts.length} color="warning" sx={{ ml: 2 }}>
                <WarningIcon color="warning" />
              </Badge>
            </Tooltip>
          )}
        </Box>

        <Box display="flex" gap={1}>
          {hasConflicts && (
            <Button
              variant={showConflicts ? 'contained' : 'outlined'}
              startIcon={showConflicts ? <VisibilityIcon /> : <TimelineIcon />}
              onClick={() => setShowConflicts(!showConflicts)}
              color="warning"
            >
              {showConflicts ? 'Hide' : 'Show'} Conflicts
            </Button>
          )}
        </Box>
      </Box>

      {/* Host Information */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Host Information
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    IP Address
                  </Typography>
                  <Typography variant="body1">
                    {host.ip_address}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Hostname
                        {conflictsByField.hostname && (
                          <Tooltip title={formatConfidenceTooltip(conflictsByField.hostname[0])}>
                            <InfoIcon fontSize="small" color="info" sx={{ ml: 0.5 }} />
                          </Tooltip>
                        )}
                      </Typography>
                      <Typography variant="body1">
                        {host.hostname || 'N/A'}
                      </Typography>
                    </Box>
                    {conflictsByField.hostname && showConflicts && (
                      <Chip
                        size="small"
                        label={`${conflictsByField.hostname[0].confidence_score}%`}
                        color={getConfidenceColor(conflictsByField.hostname[0].confidence_score)}
                      />
                    )}
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        State
                        {conflictsByField.state && (
                          <Tooltip title={formatConfidenceTooltip(conflictsByField.state[0])}>
                            <InfoIcon fontSize="small" color="info" sx={{ ml: 0.5 }} />
                          </Tooltip>
                        )}
                      </Typography>
                      <Chip
                        label={host.state || 'unknown'}
                        color={getStateColor(host.state)}
                        size="small"
                      />
                    </Box>
                    {conflictsByField.state && showConflicts && (
                      <Chip
                        size="small"
                        label={`${conflictsByField.state[0].confidence_score}%`}
                        color={getConfidenceColor(conflictsByField.state[0].confidence_score)}
                      />
                    )}
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Operating System
                        {conflictsByField.os_name && (
                          <Tooltip title={formatConfidenceTooltip(conflictsByField.os_name[0])}>
                            <InfoIcon fontSize="small" color="info" sx={{ ml: 0.5 }} />
                          </Tooltip>
                        )}
                      </Typography>
                      <Typography variant="body1">
                        {host.os_name || 'Unknown'}
                      </Typography>
                    </Box>
                    {conflictsByField.os_name && showConflicts && (
                      <Chip
                        size="small"
                        label={`${conflictsByField.os_name[0].confidence_score}%`}
                        color={getConfidenceColor(conflictsByField.os_name[0].confidence_score)}
                      />
                    )}
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Port Summary
              </Typography>
              <Box display="flex" flexDirection="column" gap={1}>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Open:</Typography>
                  <Chip label={openPorts.length} color="success" size="small" />
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Closed:</Typography>
                  <Chip label={closedPorts.length} color="error" size="small" />
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Filtered:</Typography>
                  <Chip label={filteredPorts.length} color="warning" size="small" />
                </Box>
                <Box display="flex" justifyContent="space-between" pt={1}>
                  <Typography variant="body2"><strong>Total:</strong></Typography>
                  <Typography variant="body2"><strong>{host.ports.length}</strong></Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Risk Analysis Section */}
      <HostRiskAnalysis hostId={parseInt(hostId!)} />

      {/* Conflicts Section */}
      {showConflicts && hasConflicts && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              <WarningIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Data Conflicts & Confidence
            </Typography>
            <Alert severity="info" sx={{ mb: 2 }}>
              This host has conflicting information from different scans. The displayed values represent the highest confidence data.
            </Alert>

            {Object.entries(conflictsByField).map(([fieldName, fieldConflicts]) => (
              <Box key={fieldName} sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1, textTransform: 'capitalize' }}>
                  {fieldName.replace('_', ' ')}
                </Typography>
                <Grid container spacing={1}>
                  {fieldConflicts.map((conflict, index) => (
                    <Grid item key={index}>
                      <Tooltip title={`${conflict.scan_type} | ${conflict.method} | Scan ID: ${conflict.scan_id}`}>
                        <Chip
                          label={`${conflict.confidence_score}% - ${conflict.scan_type}`}
                          color={getConfidenceColor(conflict.confidence_score)}
                          size="small"
                          variant={index === 0 ? 'filled' : 'outlined'}
                        />
                      </Tooltip>
                    </Grid>
                  ))}
                </Grid>
                {fieldConflicts.length > 1 && (
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                    {fieldConflicts.length} different values detected across scans
                  </Typography>
                )}
                <Divider sx={{ mt: 1 }} />
              </Box>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Ports Details */}
      <Paper>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>
            <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Port Details
          </Typography>

          {/* Open Ports */}
          {openPorts.length > 0 && (
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">
                  Open Ports ({openPorts.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>Version</TableCell>
                        <TableCell>State</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {openPorts.map((port) => (
                        <TableRow key={port.id}>
                          <TableCell>{port.port_number}</TableCell>
                          <TableCell>{port.protocol}</TableCell>
                          <TableCell>{port.service_name || 'Unknown'}</TableCell>
                          <TableCell>
                            {port.service_product && port.service_version
                              ? `${port.service_product} ${port.service_version}`
                              : port.service_product || 'N/A'
                            }
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={port.state || 'unknown'}
                              color={getStateColor(port.state)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Closed Ports */}
          {closedPorts.length > 0 && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">
                  Closed Ports ({closedPorts.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>State</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {closedPorts.map((port) => (
                        <TableRow key={port.id}>
                          <TableCell>{port.port_number}</TableCell>
                          <TableCell>{port.protocol}</TableCell>
                          <TableCell>{port.service_name || 'Unknown'}</TableCell>
                          <TableCell>
                            <Chip
                              label={port.state || 'unknown'}
                              color={getStateColor(port.state)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Filtered Ports */}
          {filteredPorts.length > 0 && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">
                  Filtered Ports ({filteredPorts.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>State</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {filteredPorts.map((port) => (
                        <TableRow key={port.id}>
                          <TableCell>{port.port_number}</TableCell>
                          <TableCell>{port.protocol}</TableCell>
                          <TableCell>{port.service_name || 'Unknown'}</TableCell>
                          <TableCell>
                            <Chip
                              label={port.state || 'unknown'}
                              color={getStateColor(port.state)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          )}
        </Box>
      </Paper>
    </Box>
  );
}