import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Tabs,
  Tab,
  Chip,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Computer as ComputerIcon,
  NetworkCheck as NetworkIcon,
} from '@mui/icons-material';
import { getScope, getScopeHostMappings, Scope, HostSubnetMapping } from '../services/api';

const ScopeDetail: React.FC = () => {
  const { scopeId } = useParams<{ scopeId: string }>();
  const navigate = useNavigate();
  const [scope, setScope] = useState<Scope | null>(null);
  const [hostMappings, setHostMappings] = useState<HostSubnetMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'subnets' | 'hosts'>('subnets');

  useEffect(() => {
    if (scopeId) {
      loadScopeDetails();
    }
  }, [scopeId]);

  const loadScopeDetails = async () => {
    try {
      setLoading(true);
      const scopeData = await getScope(Number(scopeId));
      const mappingsData = await getScopeHostMappings(Number(scopeId));
      
      setScope(scopeData);
      setHostMappings(mappingsData);
      setError(null);
    } catch (err) {
      setError('Failed to load scope details');
      console.error('Error loading scope details:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (error || !scope) {
    return (
      <Box p={3}>
        <Alert severity="error">
          {error || 'Scope not found'}
        </Alert>
      </Box>
    );
  }

  const getUniqueHosts = () => {
    const uniqueHosts = new Map();
    hostMappings.forEach(mapping => {
      if (!uniqueHosts.has(mapping.host_id)) {
        uniqueHosts.set(mapping.host_id, mapping);
      }
    });
    return Array.from(uniqueHosts.values());
  };

  const getHostsForSubnet = (subnetId: number) => {
    return hostMappings.filter(mapping => mapping.subnet_id === subnetId);
  };

  return (
    <Box p={3}>
      {/* Header */}
      <Box mb={4}>
        <Box display="flex" alignItems="center" mb={2}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate('/scopes')}
            sx={{ mr: 2 }}
          >
            Back to Scopes
          </Button>
          <Typography variant="h4" component="h1">
            {scope.name}
          </Typography>
        </Box>
        {scope.description && (
          <Typography variant="body1" color="textSecondary" paragraph>
            {scope.description}
          </Typography>
        )}
        <Typography variant="caption" color="textSecondary">
          Created: {new Date(scope.created_at).toLocaleString()}
        </Typography>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <NetworkIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h4" color="primary">
                  {scope.subnets.length}
                </Typography>
              </Box>
              <Typography color="textSecondary">
                Total Subnets
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <ComputerIcon color="success" sx={{ mr: 1 }} />
                <Typography variant="h4" color="success.main">
                  {getUniqueHosts().length}
                </Typography>
              </Box>
              <Typography color="textSecondary">
                Mapped Hosts
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Typography variant="h4" color="secondary.main">
                {hostMappings.length}
              </Typography>
              <Typography color="textSecondary">
                Total Mappings
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onChange={(_, newValue) => setActiveTab(newValue)}
        sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}
      >
        <Tab 
          label={`Subnets (${scope.subnets.length})`} 
          value="subnets" 
        />
        <Tab 
          label={`Mapped Hosts (${getUniqueHosts().length})`} 
          value="hosts" 
        />
      </Tabs>

      {/* Subnets Tab */}
      {activeTab === 'subnets' && (
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Subnet (CIDR)</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell align="right">Mapped Hosts</TableCell>
                  <TableCell>Created</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {scope.subnets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography color="textSecondary">
                        No subnets defined in this scope.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  scope.subnets.map((subnet) => {
                    const hostsInSubnet = getHostsForSubnet(subnet.id);
                    return (
                      <TableRow key={subnet.id}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace" fontWeight="bold">
                            {subnet.cidr}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {subnet.description || (
                            <Typography variant="body2" color="textSecondary">
                              No description
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell align="right">
                          <Chip
                            label={hostsInSubnet.length}
                            color={hostsInSubnet.length > 0 ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(subnet.created_at).toLocaleDateString()}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Hosts Tab */}
      {activeTab === 'hosts' && (
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Host ID</TableCell>
                  <TableCell>Subnets</TableCell>
                  <TableCell align="right">Subnet Count</TableCell>
                  <TableCell>Mapped Date</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {getUniqueHosts().length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography color="textSecondary">
                        No hosts mapped to this scope's subnets.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  getUniqueHosts().map((mapping) => {
                    const hostSubnets = hostMappings.filter(m => m.host_id === mapping.host_id);
                    return (
                      <TableRow key={mapping.host_id}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            Host #{mapping.host_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box display="flex" flexWrap="wrap" gap={0.5}>
                            {hostSubnets.slice(0, 3).map((subnetMapping, idx) => (
                              <Chip
                                key={idx}
                                label={subnetMapping.subnet.cidr}
                                size="small"
                                variant="outlined"
                              />
                            ))}
                            {hostSubnets.length > 3 && (
                              <Chip
                                label={`+${hostSubnets.length - 3} more`}
                                size="small"
                                color="secondary"
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell align="right">
                          <Chip
                            label={hostSubnets.length}
                            color={hostSubnets.length > 1 ? 'warning' : 'success'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(mapping.created_at).toLocaleDateString()}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}
    </Box>
  );
};

export default ScopeDetail;