import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Chip,
  Alert,
  CircularProgress,
  Divider,
  IconButton,
  Collapse,
  Button,
  Tooltip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  Warning as WarningIcon,
  OpenInNew as OpenIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface HighRiskHost {
  host_id: number;
  ip_address: string;
  hostname: string;
  os_name: string;
  risk_score: number;
  risk_level: string;
  vulnerability_count: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  risk_summary: string;
  top_vulnerabilities: Array<{
    cve_id: string;
    title: string;
    severity: string;
    cvss_score: number;
    exploitability: string;
  }>;
  critical_findings: Array<{
    finding_type: string;
    title: string;
    severity: string;
    risk_score: number;
  }>;
  recommendations: string[];
}

const CriticalFindingsWidget: React.FC = () => {
  const [highRiskHosts, setHighRiskHosts] = useState<HighRiskHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedHost, setExpandedHost] = useState<number | null>(null);
  const { token } = useAuth();

  useEffect(() => {
    if (token) {
      fetchHighRiskHosts();
    }
  }, [token]);

  const fetchHighRiskHosts = async () => {
    if (!token) {
      setError('Authentication required');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch('/api/v1/risk/hosts/high-risk?limit=10&min_risk_score=70', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch high-risk hosts: ${response.status}`);
      }
      const data = await response.json();

      // Handle new response format with empty state
      if (data.hosts !== undefined) {
        setHighRiskHosts(data.hosts);
        // Store empty state data for display
        (window as any).criticalFindingsEmptyState = data.empty_state;
        (window as any).criticalFindingsHasData = data.has_data;
      } else {
        // Fallback for old format
        setHighRiskHosts(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load critical findings');
      console.error('Error fetching high-risk hosts:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleHostClick = (hostId: number) => {
    window.location.href = `/hosts/${hostId}`;
  };

  const handleExpandToggle = (hostId: number, event: React.MouseEvent) => {
    event.stopPropagation();
    setExpandedHost(expandedHost === hostId ? null : hostId);
  };

  const getSeverityColor = (severity: string): "error" | "warning" | "info" | "success" | "default" => {
    switch (severity.toLowerCase()) {
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

  const getVulnerabilityIcon = (exploitability: string) => {
    if (exploitability && exploitability.toLowerCase().includes('high')) {
      return <BugIcon color="error" />;
    }
    return <SecurityIcon color="warning" />;
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Critical Security Findings
          </Typography>
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
          <Typography variant="h6" gutterBottom>
            Critical Security Findings
          </Typography>
          <Alert severity="error">
            <strong>Failed to Load Critical Findings</strong><br/>
            {error.includes('404') || error.includes('Not Found') ?
              'Risk assessment service is not available. Contact your administrator.' :
              'Unable to connect to the risk assessment service. Please try again later.'
            }
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const criticalHosts = highRiskHosts.filter(host => host.risk_level === 'critical');
  const highRiskHostsFiltered = highRiskHosts.filter(host => host.risk_level === 'high');

  // Check for empty state from the API response
  const emptyState = (window as any).criticalFindingsEmptyState;
  const hasData = (window as any).criticalFindingsHasData;

  return (
    <Card>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">
            Critical Security Findings
          </Typography>
          {highRiskHosts.length > 0 && (
            <Chip
              label={`${criticalHosts.length + highRiskHostsFiltered.length} hosts need attention`}
              color="error"
              size="small"
            />
          )}
        </Box>

        {highRiskHosts.length === 0 ? (
          <Alert
            severity={emptyState?.is_positive ? "success" : "info"}
            action={
              emptyState?.action_text && (
                <Tooltip title="Go to the hosts page where you can select individual hosts and run security assessments to analyze vulnerabilities, exposed services, and configuration risks.">
                  <Button
                    color="inherit"
                    size="small"
                    onClick={() => window.location.href = emptyState.action_url}
                  >
                    {emptyState.action_text}
                  </Button>
                </Tooltip>
              )
            }
          >
            <Typography variant="body2">
              <strong>{emptyState?.title || 'No Critical Security Findings'}</strong><br/>
              {emptyState?.message || 'No critical security findings detected. All hosts appear to be secure.'}
            </Typography>
          </Alert>
        ) : (
          <List sx={{ p: 0 }}>
            {highRiskHosts.map((host, index) => (
              <React.Fragment key={host.host_id}>
                <ListItemButton
                  onClick={() => handleHostClick(host.host_id)}
                  sx={{
                    borderRadius: 1,
                    mb: 1,
                    border: 1,
                    borderColor: host.risk_level === 'critical' ? 'error.main' : 'warning.main',
                    backgroundColor: host.risk_level === 'critical' ? 'error.light' : 'warning.light',
                    '&:hover': {
                      backgroundColor: host.risk_level === 'critical' ? 'error.dark' : 'warning.dark',
                    },
                  }}
                >
                  <ListItemIcon>
                    {host.risk_level === 'critical' ? (
                      <WarningIcon color="error" />
                    ) : (
                      <SecurityIcon color="warning" />
                    )}
                  </ListItemIcon>

                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1} flexWrap="wrap">
                        <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                          {host.ip_address}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {host.hostname || 'Unknown'}
                        </Typography>
                        <Chip
                          label={host.risk_level.toUpperCase()}
                          color={getSeverityColor(host.risk_level)}
                          size="small"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" sx={{ mb: 0.5 }}>
                          Risk Score: {host.risk_score.toFixed(1)} | {host.vulnerability_count} vulnerabilities
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {host.os_name} • {host.critical_vulnerabilities} critical, {host.high_vulnerabilities} high
                        </Typography>
                      </Box>
                    }
                  />

                  <Box display="flex" alignItems="center" gap={1}>
                    <IconButton
                      size="small"
                      onClick={(e) => handleExpandToggle(host.host_id, e)}
                      sx={{ color: 'inherit' }}
                    >
                      {expandedHost === host.host_id ? <CollapseIcon /> : <ExpandIcon />}
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleHostClick(host.host_id);
                      }}
                      sx={{ color: 'inherit' }}
                    >
                      <OpenIcon />
                    </IconButton>
                  </Box>
                </ListItemButton>

                <Collapse in={expandedHost === host.host_id} timeout="auto" unmountOnExit>
                  <Box sx={{ ml: 4, mr: 2, mb: 2, p: 2, bgcolor: 'background.paper', borderRadius: 1, border: 1, borderColor: 'divider' }}>
                    {/* Risk Summary */}
                    <Typography variant="body2" sx={{ mb: 2, fontStyle: 'italic' }}>
                      {host.risk_summary}
                    </Typography>

                    {/* Top Vulnerabilities */}
                    {host.top_vulnerabilities.length > 0 && (
                      <Box mb={2}>
                        <Typography variant="subtitle2" gutterBottom>
                          Top Vulnerabilities:
                        </Typography>
                        {host.top_vulnerabilities.slice(0, 3).map((vuln, idx) => (
                          <Box key={idx} display="flex" alignItems="center" gap={1} mb={1}>
                            {getVulnerabilityIcon(vuln.exploitability)}
                            <Box flex={1}>
                              <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                                {vuln.cve_id}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                CVSS: {vuln.cvss_score} | {vuln.exploitability} exploitability
                              </Typography>
                            </Box>
                            <Chip
                              label={vuln.severity}
                              color={getSeverityColor(vuln.severity)}
                              size="small"
                            />
                          </Box>
                        ))}
                      </Box>
                    )}

                    {/* Critical Findings */}
                    {host.critical_findings.length > 0 && (
                      <Box mb={2}>
                        <Typography variant="subtitle2" gutterBottom>
                          Security Issues:
                        </Typography>
                        {host.critical_findings.slice(0, 2).map((finding, idx) => (
                          <Box key={idx} display="flex" alignItems="center" gap={1} mb={1}>
                            <WarningIcon color="warning" fontSize="small" />
                            <Box flex={1}>
                              <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                                {finding.title}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {finding.finding_type} • Risk: {finding.risk_score.toFixed(1)}
                              </Typography>
                            </Box>
                          </Box>
                        ))}
                      </Box>
                    )}

                    {/* Recommendations */}
                    {host.recommendations && host.recommendations.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Immediate Actions:
                        </Typography>
                        {host.recommendations.slice(0, 2).map((recommendation, idx) => (
                          <Typography
                            key={idx}
                            variant="body2"
                            sx={{
                              mb: 0.5,
                              pl: 2,
                              position: 'relative',
                              '&:before': {
                                content: '"→"',
                                position: 'absolute',
                                left: 0,
                                color: 'primary.main',
                              },
                            }}
                          >
                            {recommendation}
                          </Typography>
                        ))}
                      </Box>
                    )}
                  </Box>
                </Collapse>

                {index < highRiskHosts.length - 1 && <Divider sx={{ my: 1 }} />}
              </React.Fragment>
            ))}
          </List>
        )}

        {highRiskHosts.length > 0 && (
          <Box mt={2} textAlign="center">
            <Typography variant="caption" color="text.secondary">
              Click any host for detailed security analysis
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default CriticalFindingsWidget;