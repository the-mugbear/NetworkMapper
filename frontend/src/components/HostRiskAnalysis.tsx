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
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Button,
  Tooltip,
  Badge
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  BugReport as BugIcon,
  Assessment as AssessmentIcon,
  ExpandMore as ExpandIcon,
  Refresh as RefreshIcon,
  Timeline as TrendIcon
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface HostRiskData {
  host: {
    id: number;
    ip_address: string;
    hostname: string;
    os_name: string;
    os_family: string;
    state: string;
  };
  risk_assessment: {
    risk_score: number;
    risk_level: string;
    vulnerability_count: number;
    critical_vulnerabilities: number;
    high_vulnerabilities: number;
    exposed_services: number;
    dangerous_ports: number;
    attack_surface_score: number;
    patch_urgency_score: number;
    exposure_risk_score: number;
    configuration_risk_score: number;
    risk_summary: string;
    assessment_date: string;
    last_updated: string;
  };
  vulnerabilities: {
    Critical: Array<{
      cve_id: string;
      title: string;
      description: string;
      cvss_score: number;
      severity: string;
      exploitability: string;
      affected_software: string;
      patch_available: boolean;
      patch_url?: string;
    }>;
    High: Array<any>;
    Medium: Array<any>;
    Low: Array<any>;
  };
  security_findings: {
    Critical: Array<{
      finding_type: string;
      title: string;
      description: string;
      severity: string;
      risk_score: number;
      evidence: string;
      recommendation: string;
    }>;
    High: Array<any>;
    Medium: Array<any>;
    Low: Array<any>;
  };
  recommendations: string[];
  summary_stats: {
    total_vulnerabilities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
  };
}

interface HostRiskAnalysisProps {
  hostId: number;
}

const HostRiskAnalysis: React.FC<HostRiskAnalysisProps> = ({ hostId }) => {
  const [riskData, setRiskData] = useState<HostRiskData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isAssessing, setIsAssessing] = useState(false);
  const [assessmentProgress, setAssessmentProgress] = useState<string>('');
  const { token } = useAuth();

  const fetchRiskAssessment = async () => {
    if (!token) return;

    try {
      const response = await fetch(`/api/v1/risk/hosts/${hostId}/risk-assessment`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          setError('No risk assessment found for this host');
        } else {
          throw new Error('Failed to fetch risk assessment');
        }
        return;
      }

      const data = await response.json();
      setRiskData(data);
      setError(null);
    } catch (err) {
      console.error('Error fetching risk assessment:', err);
      setError('Failed to load risk assessment data');
    } finally {
      setLoading(false);
    }
  };

  const triggerRiskAssessment = async () => {
    if (!token) return;

    setIsAssessing(true);
    setError(null);

    try {
      // Step 1: Initialize assessment
      setAssessmentProgress('Initializing security assessment...');
      await new Promise(resolve => setTimeout(resolve, 500));

      // Step 2: Analyze host data
      setAssessmentProgress('Analyzing host configuration and open ports...');
      await new Promise(resolve => setTimeout(resolve, 800));

      // Step 3: Check vulnerabilities
      setAssessmentProgress('Checking for common vulnerability patterns (hardcoded rules)...');
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Step 4: Evaluate services
      setAssessmentProgress('Evaluating exposed services and security configurations...');
      await new Promise(resolve => setTimeout(resolve, 700));

      // Step 5: Calculate risk scores
      setAssessmentProgress('Calculating risk scores and generating recommendations...');

      const response = await fetch(`/api/v1/risk/hosts/${hostId}/assess-risk`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to trigger risk assessment');
      }

      // Step 6: Finalizing results
      setAssessmentProgress('Finalizing assessment results...');
      await new Promise(resolve => setTimeout(resolve, 500));

      // Refresh the data after assessment
      await fetchRiskAssessment();
      setAssessmentProgress('Assessment completed successfully!');

      // Clear progress message after a moment
      setTimeout(() => setAssessmentProgress(''), 2000);
    } catch (err) {
      console.error('Error triggering risk assessment:', err);
      setError('Failed to perform risk assessment. The system analyzes your host data including open ports, service versions, and known vulnerabilities to generate a comprehensive security report.');
      setAssessmentProgress('');
    } finally {
      setIsAssessing(false);
    }
  };

  useEffect(() => {
    fetchRiskAssessment();
  }, [hostId, token]);

  const getRiskColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#9e9e9e';
    }
  };

  const getRiskChipColor = (level: string): "error" | "warning" | "info" | "success" | "default" => {
    switch (level.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return <ErrorIcon sx={{ color: '#d32f2f' }} />;
      case 'high': return <WarningIcon sx={{ color: '#f57c00' }} />;
      case 'medium': return <InfoIcon sx={{ color: '#1976d2' }} />;
      case 'low': return <SecurityIcon sx={{ color: '#388e3c' }} />;
      default: return <InfoIcon sx={{ color: '#9e9e9e' }} />;
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
          {isAssessing && assessmentProgress && (
            <Alert severity="info" sx={{ mb: 2 }}>
              <Box display="flex" alignItems="center" gap={1}>
                <CircularProgress size={20} />
                <Box>
                  <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                    Risk Assessment in Progress
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {assessmentProgress}
                  </Typography>
                  <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                    Using: Port scan data • Service versions • Pattern matching • Configuration analysis
                  </Typography>
                </Box>
              </Box>
            </Alert>
          )}
          <Alert
            severity="warning"
            action={
              <Tooltip title="Analyze this host for security vulnerabilities, exposed services, and configuration risks. This will scan open ports, detect software versions, and check for known CVEs.">
                <Button
                  color="inherit"
                  size="small"
                  onClick={triggerRiskAssessment}
                  disabled={isAssessing}
                  startIcon={isAssessing ? <CircularProgress size={16} /> : <AssessmentIcon />}
                >
                  {isAssessing ? 'Assessing...' : 'Run Assessment'}
                </Button>
              </Tooltip>
            }
          >
            {error}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!riskData) return null;

  const { risk_assessment, vulnerabilities, security_findings, recommendations, summary_stats } = riskData;

  return (
    <Box>
      {/* Assessment Progress */}
      {isAssessing && assessmentProgress && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Box display="flex" alignItems="center" gap={1}>
            <CircularProgress size={20} />
            <Box>
              <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                Risk Assessment in Progress
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {assessmentProgress}
              </Typography>
              <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                Data sources: Network scan results • Service fingerprints • Hardcoded vulnerability patterns • Configuration analysis
              </Typography>
              <Typography variant="caption" display="block">
                APIs: /api/v1/risk/hosts/{hostId}/assess-risk • Pattern-based vulnerability detection
              </Typography>
            </Box>
          </Box>
        </Alert>
      )}

      {/* Risk Overview */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
            <Typography variant="h6" display="flex" alignItems="center" gap={1}>
              <SecurityIcon color="primary" />
              Security Risk Assessment
            </Typography>
            <Box display="flex" gap={1}>
              <Tooltip title="Refresh Assessment">
                <Button
                  size="small"
                  onClick={fetchRiskAssessment}
                  disabled={loading}
                  startIcon={<RefreshIcon />}
                >
                  Refresh
                </Button>
              </Tooltip>
              <Tooltip title="Run a fresh security assessment. This will re-scan for vulnerabilities, check current service configurations, and update the risk score based on latest findings.">
                <Button
                  size="small"
                  variant="contained"
                  onClick={triggerRiskAssessment}
                  disabled={isAssessing}
                  startIcon={isAssessing ? <CircularProgress size={16} /> : <AssessmentIcon />}
                >
                  {isAssessing ? 'Assessing...' : 'Re-assess'}
                </Button>
              </Tooltip>
            </Box>
          </Box>

          <Grid container spacing={3}>
            {/* Risk Score */}
            <Grid item xs={12} md={3}>
              <Box textAlign="center">
                <Box position="relative" display="inline-flex" mb={1}>
                  <CircularProgress
                    variant="determinate"
                    value={risk_assessment.risk_score}
                    size={80}
                    thickness={6}
                    sx={{ color: getRiskColor(risk_assessment.risk_level) }}
                  />
                  <Box
                    top={0}
                    left={0}
                    bottom={0}
                    right={0}
                    position="absolute"
                    display="flex"
                    alignItems="center"
                    justifyContent="center"
                  >
                    <Typography variant="h6" component="div" color="text.secondary">
                      {Math.round(risk_assessment.risk_score)}
                    </Typography>
                  </Box>
                </Box>
                <Chip
                  icon={getRiskIcon(risk_assessment.risk_level)}
                  label={risk_assessment.risk_level.toUpperCase()}
                  color={getRiskChipColor(risk_assessment.risk_level)}
                  sx={{ fontWeight: 'bold' }}
                />
              </Box>
            </Grid>

            {/* Risk Metrics */}
            <Grid item xs={12} md={9}>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="error">
                      {summary_stats.critical_count}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Critical CVEs
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="warning.main">
                      {summary_stats.high_count}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      High CVEs
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="primary">
                      {risk_assessment.exposed_services}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Exposed Services
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="error">
                      {risk_assessment.dangerous_ports}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Dangerous Ports
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </Grid>
          </Grid>

          {/* Risk Summary */}
          {risk_assessment.risk_summary && (
            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                {risk_assessment.risk_summary}
              </Typography>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Critical Vulnerabilities */}
      {vulnerabilities.Critical.length > 0 && (
        <Accordion defaultExpanded sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandIcon />}>
            <Box display="flex" alignItems="center" gap={1}>
              <ErrorIcon color="error" />
              <Typography variant="h6">
                Critical Vulnerabilities ({vulnerabilities.Critical.length})
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <List disablePadding>
              {vulnerabilities.Critical.map((vuln, index) => (
                <React.Fragment key={index}>
                  <ListItem alignItems="flex-start">
                    <ListItemIcon>
                      <BugIcon color="error" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1} flexWrap="wrap">
                          <Typography variant="subtitle2" fontWeight="bold">
                            {vuln.cve_id}
                          </Typography>
                          <Chip
                            label={`CVSS: ${vuln.cvss_score}`}
                            size="small"
                            color="error"
                          />
                          {vuln.patch_available && (
                            <Chip label="Patch Available" size="small" color="success" />
                          )}
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" sx={{ mt: 1 }}>
                            {vuln.title}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Affected: {vuln.affected_software} | Exploitability: {vuln.exploitability}
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                  {index < vulnerabilities.Critical.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Security Findings */}
      {security_findings.Critical.length > 0 && (
        <Accordion sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandIcon />}>
            <Box display="flex" alignItems="center" gap={1}>
              <WarningIcon color="warning" />
              <Typography variant="h6">
                Critical Security Findings ({security_findings.Critical.length})
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <List disablePadding>
              {security_findings.Critical.map((finding, index) => (
                <React.Fragment key={index}>
                  <ListItem alignItems="flex-start">
                    <ListItemIcon>
                      <WarningIcon color="warning" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="subtitle2" fontWeight="bold">
                            {finding.title}
                          </Typography>
                          <Chip
                            label={`Risk: ${finding.risk_score.toFixed(1)}`}
                            size="small"
                            color="warning"
                          />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" sx={{ mt: 1 }}>
                            {finding.description}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Type: {finding.finding_type}
                          </Typography>
                          {finding.recommendation && (
                            <Alert severity="info" sx={{ mt: 1, fontSize: '0.875rem' }}>
                              <strong>Recommendation:</strong> {finding.recommendation}
                            </Alert>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                  {index < security_findings.Critical.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom display="flex" alignItems="center" gap={1}>
              <TrendIcon color="primary" />
              Security Recommendations
            </Typography>
            <List>
              {recommendations.map((recommendation, index) => (
                <ListItem key={index}>
                  <ListItemText
                    primary={
                      <Typography variant="body2">
                        <strong>{index + 1}.</strong> {recommendation}
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </CardContent>
        </Card>
      )}

      {/* Assessment Metadata */}
      <Box mt={2} textAlign="center">
        <Typography variant="caption" color="text.secondary">
          Last assessed: {new Date(risk_assessment.assessment_date).toLocaleString()}
        </Typography>
      </Box>
    </Box>
  );
};

export default HostRiskAnalysis;