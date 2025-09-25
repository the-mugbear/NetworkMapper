import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  CircularProgress,
  Alert,
  Button,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { getScopeCoverage, ScopeCoverageSummary } from '../services/api';

const ScopeCoverageWidget: React.FC = () => {
  const [coverage, setCoverage] = useState<ScopeCoverageSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchCoverage = async () => {
      try {
        setLoading(true);
        const data = await getScopeCoverage();
        setCoverage(data);
        setError(null);
      } catch (err) {
        console.error('Error fetching scope coverage:', err);
        setError('Failed to load scope coverage');
      } finally {
        setLoading(false);
      }
    };

    fetchCoverage();
  }, []);

  const coverageChipColor = (() => {
    if (!coverage) return 'default' as const;
    if (coverage.coverage_percentage >= 90) return 'success' as const;
    if (coverage.coverage_percentage >= 50) return 'warning' as const;
    if (coverage.coverage_percentage > 0) return 'error' as const;
    return 'default' as const;
  })();

  if (loading) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box display="flex" justifyContent="center" alignItems="center" minHeight={200}>
            <CircularProgress />
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error || !coverage) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Alert severity="error">{error || 'Scope coverage is unavailable.'}</Alert>
          <Button sx={{ mt: 2 }} onClick={() => navigate('/scopes')} variant="outlined" size="small">
            Manage scopes
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">Scope Coverage</Typography>
          <Chip
            label={`${coverage.coverage_percentage.toFixed(1)}% covered`}
            color={coverageChipColor}
            variant={coverageChipColor === 'default' ? 'outlined' : 'filled'}
            size="small"
          />
        </Box>

        <Grid container spacing={2} mb={coverage.out_of_scope_hosts ? 2 : 0}>
          <Grid item xs={6}>
            <Box textAlign="center">
              <Typography variant="h5" color="primary">
                {coverage.total_hosts}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total Hosts
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6}>
            <Box textAlign="center">
              <Typography variant="h5" color={coverage.out_of_scope_hosts ? 'error.main' : 'success.main'}>
                {coverage.out_of_scope_hosts}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Out of Scope
              </Typography>
            </Box>
          </Grid>
        </Grid>

        {coverage.out_of_scope_hosts > 0 ? (
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Recently seen outside configured scopes
            </Typography>
            <List dense sx={{ maxHeight: 220, overflow: 'auto' }}>
              {coverage.recent_out_of_scope_hosts.map((host) => {
                const lastSeen = host.last_seen ? new Date(host.last_seen).toLocaleString() : 'Unknown';
                return (
                  <ListItem disablePadding key={`dash-oos-${host.host_id}`}>
                    <ListItemButton onClick={() => navigate(`/hosts/${host.host_id}`)}>
                      <ListItemText
                        primary={
                          <Typography variant="subtitle2" fontFamily="monospace">
                            {host.ip_address}
                          </Typography>
                        }
                        secondary={
                          <Typography variant="body2" color="text.secondary">
                            {host.hostname || 'Unknown host'} · Last seen {lastSeen}
                          </Typography>
                        }
                      />
                    </ListItemButton>
                  </ListItem>
                );
              })}
            </List>
            <Button
              variant="text"
              size="small"
              sx={{ mt: 1 }}
              onClick={() => navigate('/hosts?out_of_scope=true')}
            >
              View all out-of-scope hosts
            </Button>
          </Box>
        ) : coverage.has_scope_configuration ? (
          <Alert severity="success">All discovered hosts map to your defined scopes.</Alert>
        ) : (
          <Alert severity="info">
            No subnet scopes configured yet. Upload a subnet file to track out-of-scope hosts.
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};

export default ScopeCoverageWidget;
