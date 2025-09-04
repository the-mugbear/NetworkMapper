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
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  ExpandMore as ExpandMoreIcon,
  Computer as ComputerIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { getHost } from '../services/api';
import type { Host } from '../services/api';

export default function HostDetail() {
  const { hostId } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const [host, setHost] = useState<Host | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHost = async () => {
      if (!hostId) return;

      try {
        const data = await getHost(parseInt(hostId));
        setHost(data);
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
      <Box display="flex" alignItems="center" mb={3}>
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
                  <Typography variant="body2" color="text.secondary">
                    Hostname
                  </Typography>
                  <Typography variant="body1">
                    {host.hostname || 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    State
                  </Typography>
                  <Chip
                    label={host.state || 'unknown'}
                    color={getStateColor(host.state)}
                    size="small"
                  />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Operating System
                  </Typography>
                  <Typography variant="body1">
                    {host.os_name || 'Unknown'}
                  </Typography>
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