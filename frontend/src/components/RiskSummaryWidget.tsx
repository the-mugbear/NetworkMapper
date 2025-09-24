import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Chip,
  LinearProgress,
  Alert,
  CircularProgress,
  Button,
  Tooltip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface RiskSummary {
  total_hosts: number;
  assessed_hosts: number;
  unassessed_hosts: number;
  risk_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  risk_percentages: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  top_risk_hosts: Array<{
    host_id: number;
    ip_address: string;
    hostname: string;
    risk_score: number;
    risk_level: string;
    vulnerability_count: number;
    last_assessment: string;
  }>;
}

const RiskSummaryWidget: React.FC = () => {
  const [riskData, setRiskData] = useState<RiskSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { token } = useAuth();

  useEffect(() => {
    if (token) {
      fetchRiskSummary();
    }
  }, [token]);

  const fetchRiskSummary = async () => {
    if (!token) {
      setError('Authentication required');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch('/api/v1/risk/hosts/risk-summary', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch risk summary: ${response.status}`);
      }
      const data = await response.json();
      setRiskData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load risk summary');
      console.error('Error fetching risk summary:', err);
    } finally {
      setLoading(false);
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return <ErrorIcon sx={{ color: '#d32f2f' }} />;
      case 'high':
        return <WarningIcon sx={{ color: '#f57c00' }} />;
      case 'medium':
        return <InfoIcon sx={{ color: '#1976d2' }} />;
      case 'low':
        return <SecurityIcon sx={{ color: '#388e3c' }} />;
      default:
        return <InfoIcon sx={{ color: '#9e9e9e' }} />;
    }
  };

  const getRiskColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return '#d32f2f';
      case 'high':
        return '#f57c00';
      case 'medium':
        return '#1976d2';
      case 'low':
        return '#388e3c';
      default:
        return '#9e9e9e';
    }
  };

  const getRiskChipColor = (level: string): "error" | "warning" | "info" | "success" | "default" => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
            <CircularProgress />
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Alert severity="error">
            <strong>Failed to Load Risk Data</strong><br/>
            {error.includes('404') || error.includes('Not Found') ?
              'Risk assessment service is not available. Contact your administrator.' :
              'Unable to connect to the risk assessment service. Please try again later.'
            }
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!riskData) {
    return null;
  }

  // Check if we have an empty state
  if (!riskData.has_data && riskData.empty_state) {
    const { empty_state } = riskData;
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Security Risk Overview
          </Typography>

          <Alert
            severity={empty_state.is_positive ? "success" : "info"}
            sx={{ mt: 2 }}
            action={
              empty_state.action_text && empty_state.action_url ? (
                <Tooltip title="Upload new scans to analyze more hosts.">
                  <Button
                    color="inherit"
                    size="small"
                    onClick={() => window.location.href = empty_state.action_url!}
                  >
                    {empty_state.action_text}
                  </Button>
                </Tooltip>
              ) : undefined
            }
          >
            <strong>{empty_state.title}</strong><br/>
            {empty_state.message}
          </Alert>

          {/* Show basic stats even in empty state */}
          <Box mt={3}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Box textAlign="center">
                  <Typography variant="h4" color="primary">
                    {riskData.total_hosts || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Hosts
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Box textAlign="center">
                  <Typography variant="h4" color="text.secondary">
                    {riskData.assessed_hosts || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Assessed
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Box>
        </CardContent>
      </Card>
    );
  }

  const criticalAndHighCount = riskData.risk_distribution.critical + riskData.risk_distribution.high;
  const totalAssessed = riskData.assessed_hosts;

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Security Risk Overview
        </Typography>

        {/* Overall Risk Status */}
        <Box mb={3}>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="error" sx={{ fontWeight: 'bold' }}>
                  {criticalAndHighCount}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Immediate Attention
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="primary">
                  {riskData.total_hosts}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Hosts
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="success.main">
                  {riskData.assessed_hosts}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Assessed
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="warning.main">
                  {riskData.unassessed_hosts}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Unassessed
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Box>

        {/* Risk Distribution */}
        <Box mb={3}>
          <Typography variant="subtitle1" gutterBottom>
            Risk Distribution
          </Typography>

          {Object.entries(riskData.risk_distribution).map(([level, count]) => {
            const percentage = riskData.risk_percentages[level as keyof typeof riskData.risk_percentages];

            return (
              <Box key={level} mb={1}>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={0.5}>
                  <Box display="flex" alignItems="center" gap={1}>
                    {getRiskIcon(level)}
                    <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                      {level}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {count} hosts ({percentage}%)
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={percentage}
                  sx={{
                    height: 8,
                    backgroundColor: 'rgba(0,0,0,0.1)',
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: getRiskColor(level),
                    },
                  }}
                />
              </Box>
            );
          })}
        </Box>

        {/* Top Risk Hosts */}
        {riskData.top_risk_hosts.length > 0 && (
          <Box>
            <Typography variant="subtitle1" gutterBottom>
              Highest Risk Hosts
            </Typography>

            {riskData.top_risk_hosts.map((host) => (
              <Card
                key={host.host_id}
                variant="outlined"
                sx={{
                  mb: 1,
                  '&:hover': {
                    backgroundColor: 'action.hover',
                    cursor: 'pointer',
                  },
                }}
                onClick={() => window.location.href = `/hosts/${host.host_id}`}
              >
                <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                  <Box display="flex" justifyContent="space-between" alignItems="center">
                    <Box>
                      <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                        {host.ip_address}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {host.hostname || 'Unknown hostname'}
                      </Typography>
                    </Box>

                    <Box textAlign="right">
                      <Chip
                        label={host.risk_level.toUpperCase()}
                        color={getRiskChipColor(host.risk_level)}
                        size="small"
                        sx={{ mb: 0.5 }}
                      />
                      <Typography variant="caption" display="block" color="text.secondary">
                        Score: {host.risk_score.toFixed(1)} | {host.vulnerability_count} CVEs
                      </Typography>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            ))}
          </Box>
        )}

        {/* Assessment Coverage Warning */}
        {riskData.unassessed_hosts > 0 && (
          <Alert
            severity="info"
            sx={{ mt: 2 }}
          >
            {riskData.unassessed_hosts} hosts have not been assessed for security risks.
            Run risk assessments for complete coverage.
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};

export default RiskSummaryWidget;
