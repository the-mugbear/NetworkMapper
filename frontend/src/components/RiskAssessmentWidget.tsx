import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  LinearProgress,
  Chip,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
} from '@mui/icons-material';
import { SubnetStats } from '../services/api';

interface RiskAssessmentWidgetProps {
  subnetStats: SubnetStats[];
}

interface RiskMetrics {
  totalSubnets: number;
  highRiskSubnets: number;
  averageUtilization: number;
  topRisks: Array<{
    subnet: string;
    risk: string;
    utilization: number;
    hosts: number;
  }>;
  recommendations: string[];
}

const RiskAssessmentWidget: React.FC<RiskAssessmentWidgetProps> = ({ subnetStats }) => {
  const calculateRiskMetrics = (): RiskMetrics => {
    const totalSubnets = subnetStats.length;
    const highRiskSubnets = subnetStats.filter(s => 
      s.risk_level === 'high' || s.risk_level === 'critical'
    ).length;
    
    const totalUtilization = subnetStats.reduce((sum, s) => 
      sum + (s.utilization_percentage || 0), 0
    );
    const averageUtilization = totalSubnets > 0 ? totalUtilization / totalSubnets : 0;
    
    // Get top 3 risk subnets
    const topRisks = subnetStats
      .filter(s => s.utilization_percentage && s.utilization_percentage > 0)
      .sort((a, b) => (b.utilization_percentage || 0) - (a.utilization_percentage || 0))
      .slice(0, 3)
      .map(s => ({
        subnet: s.cidr,
        risk: s.risk_level || 'unknown',
        utilization: s.utilization_percentage || 0,
        hosts: s.host_count
      }));
    
    // Generate recommendations
    const recommendations = [];
    if (averageUtilization > 50) {
      recommendations.push('Consider network segmentation for high-utilization subnets');
    }
    if (highRiskSubnets > 0) {
      recommendations.push(`Review security controls for ${highRiskSubnets} high-risk subnet(s)`);
    }
    const publicSubnets = subnetStats.filter(s => !s.is_private).length;
    if (publicSubnets > 0) {
      recommendations.push(`Audit ${publicSubnets} public subnet(s) for proper access controls`);
    }
    if (recommendations.length === 0) {
      recommendations.push('Network risk profile appears acceptable');
    }
    
    return {
      totalSubnets,
      highRiskSubnets,
      averageUtilization,
      topRisks,
      recommendations
    };
  };

  if (subnetStats.length === 0) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" mb={2}>
            <SecurityIcon color="action" sx={{ mr: 1 }} />
            <Typography variant="h6">Risk Assessment</Typography>
          </Box>
          <Typography color="textSecondary">
            No subnet data available for risk assessment.
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const metrics = calculateRiskMetrics();
  
  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return <ErrorIcon color="error" />;
      case 'high': return <WarningIcon color="warning" />;
      case 'medium': return <InfoIcon color="info" />;
      case 'low': return <CheckCircleIcon color="success" />;
      default: return <SecurityIcon color="action" />;
    }
  };

  const getUtilizationColor = (utilization: number) => {
    if (utilization >= 80) return 'error';
    if (utilization >= 60) return 'warning';
    if (utilization >= 40) return 'info';
    return 'success';
  };

  return (
    <Card>
      <CardContent>
        <Box display="flex" alignItems="center" mb={2}>
          <AssessmentIcon color="primary" sx={{ mr: 1 }} />
          <Typography variant="h6">Network Risk Assessment</Typography>
        </Box>

        {/* Overall Risk Level */}
        <Box mb={3}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
            <Typography variant="body2" color="textSecondary">
              Average Network Utilization
            </Typography>
            <Typography variant="h6" color={getUtilizationColor(metrics.averageUtilization)}>
              {metrics.averageUtilization.toFixed(1)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={Math.min(metrics.averageUtilization, 100)}
            color={getUtilizationColor(metrics.averageUtilization)}
            sx={{ height: 8, borderRadius: 4 }}
          />
        </Box>

        {/* Risk Summary */}
        <Box display="flex" gap={1} mb={3} flexWrap="wrap">
          <Chip
            icon={<SecurityIcon />}
            label={`${metrics.totalSubnets} Total Subnets`}
            color="primary"
            variant="outlined"
            size="small"
          />
          <Chip
            icon={<WarningIcon />}
            label={`${metrics.highRiskSubnets} High Risk`}
            color={metrics.highRiskSubnets > 0 ? 'warning' : 'default'}
            variant="outlined"
            size="small"
          />
          <Chip
            icon={<TrendingUpIcon />}
            label={`${metrics.averageUtilization.toFixed(0)}% Avg Utilization`}
            color={getUtilizationColor(metrics.averageUtilization)}
            variant="outlined"
            size="small"
          />
        </Box>

        {/* Top Risk Subnets */}
        {metrics.topRisks.length > 0 && (
          <>
            <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
              Top Risk Subnets
            </Typography>
            <List dense>
              {metrics.topRisks.map((risk, index) => (
                <ListItem key={index} disableGutters>
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    {getRiskIcon(risk.risk)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1}>
                        <Typography variant="body2" fontFamily="monospace">
                          {risk.subnet}
                        </Typography>
                        <Chip
                          label={`${risk.utilization.toFixed(1)}%`}
                          size="small"
                          color={getUtilizationColor(risk.utilization)}
                          variant="outlined"
                        />
                      </Box>
                    }
                    secondary={`${risk.hosts} discovered hosts`}
                  />
                </ListItem>
              ))}
            </List>
            <Divider sx={{ my: 2 }} />
          </>
        )}

        {/* Recommendations */}
        <Typography variant="subtitle2" gutterBottom>
          Security Recommendations
        </Typography>
        {metrics.recommendations.map((rec, index) => (
          <Alert 
            key={index} 
            severity={index === 0 && metrics.highRiskSubnets > 0 ? 'warning' : 'info'}
            sx={{ mb: 1, fontSize: '0.875rem' }}
          >
            {rec}
          </Alert>
        ))}
      </CardContent>
    </Card>
  );
};

export default RiskAssessmentWidget;