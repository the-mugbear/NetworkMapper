import React from 'react';
import {
  Tooltip,
  Box,
  Typography,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Link,
} from '@mui/material';
import {
  Info as InfoIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface RiskTooltipProps {
  children: React.ReactElement;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  portNumber?: number;
  serviceName?: string;
  customReason?: string;
}

const riskConfig = {
  Critical: {
    color: '#d32f2f',
    icon: <ErrorIcon />,
    description: 'Immediate security threat requiring urgent attention',
    commonReasons: [
      'Administrative access exposed to untrusted networks',
      'Unencrypted protocols handling sensitive data',
      'Database services without proper access controls',
      'Services with known public exploits',
    ],
  },
  High: {
    color: '#f57c00',
    icon: <WarningIcon />,
    description: 'Significant security concern requiring prompt attention',
    commonReasons: [
      'Services on non-standard ports (potential evasion)',
      'Protocols with known security limitations',
      'Services commonly misconfigured',
      'High-value targets with elevated privileges',
    ],
  },
  Medium: {
    color: '#fbc02d',
    icon: <InfoIcon />,
    description: 'Security issue requiring attention but not immediately critical',
    commonReasons: [
      'Services requiring hardening or monitoring',
      'Protocols that may leak information',
      'Default configurations requiring review',
      'Services indicating potential compromise',
    ],
  },
  Low: {
    color: '#388e3c',
    icon: <CheckCircleIcon />,
    description: 'Generally safe service that should be documented',
    commonReasons: [
      'Standard services on expected ports',
      'Properly configured encrypted services',
      'Services with appropriate access controls',
      'Development services in isolated environments',
    ],
  },
};

const getPortSpecificRisk = (port: number, service?: string): string => {
  const portRisks: { [key: number]: string } = {
    22: 'SSH provides direct system access and is a primary target for attackers. Ensure strong authentication and access controls.',
    23: 'Telnet transmits credentials in plaintext. Consider replacing with SSH for secure remote access.',
    21: 'FTP may transmit credentials in plaintext. Consider SFTP or FTPS for secure file transfer.',
    80: 'HTTP transmits data without encryption. Ensure sensitive operations use HTTPS instead.',
    443: 'HTTPS service - verify SSL/TLS configuration and certificate validity.',
    3389: 'RDP provides desktop access. Ensure strong authentication and network access controls.',
    3306: 'MySQL database - verify access is restricted to authorized applications only.',
    5432: 'PostgreSQL database - ensure proper authentication and network restrictions.',
    1433: 'Microsoft SQL Server - verify access controls and authentication mechanisms.',
    445: 'SMB file sharing - commonly targeted for lateral movement and data exfiltration.',
    135: 'Microsoft RPC service - often used in attack chains for privilege escalation.',
    139: 'NetBIOS service - can leak system information and facilitate network reconnaissance.',
    161: 'SNMP service - verify community strings are not default values (public/private).',
    25: 'SMTP mail service - verify relay restrictions and authentication requirements.',
    53: 'DNS service - ensure zone transfers are restricted and recursion is properly configured.',
    8080: 'HTTP alternative port - often used to bypass security controls or hide services.',
    8443: 'HTTPS alternative port - verify this is an intentional service and properly secured.',
  };

  if (portRisks[port]) {
    return portRisks[port];
  }

  if (service) {
    const serviceRisks: { [key: string]: string } = {
      'ssh': 'Secure Shell service - ensure key-based authentication and proper access controls.',
      'http': 'Web server - verify security headers and input validation are properly implemented.',
      'https': 'Secure web server - verify SSL/TLS configuration meets current security standards.',
      'ftp': 'File transfer service - consider using secure alternatives like SFTP.',
      'mysql': 'Database service - ensure access is restricted to authorized applications.',
      'postgresql': 'Database service - verify authentication and authorization controls.',
      'smtp': 'Mail server - verify authentication and relay restrictions are configured.',
      'dns': 'Domain name service - ensure recursion and zone transfers are properly restricted.',
    };
    
    const serviceLower = service.toLowerCase();
    if (serviceRisks[serviceLower]) {
      return serviceRisks[serviceLower];
    }
  }

  return 'Review this service to ensure it follows security best practices for your environment.';
};

export default function RiskTooltip({ 
  children, 
  riskLevel, 
  portNumber, 
  serviceName, 
  customReason 
}: RiskTooltipProps) {
  const navigate = useNavigate();
  const config = riskConfig[riskLevel];
  
  const tooltipContent = (
    <Box sx={{ maxWidth: 400, p: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Box sx={{ color: config.color, mr: 1 }}>
          {config.icon}
        </Box>
        <Chip 
          label={`${riskLevel} Risk`}
          sx={{ 
            backgroundColor: config.color,
            color: 'white',
            fontWeight: 'bold',
            mr: 1
          }}
        />
        {portNumber && (
          <Chip 
            label={`Port ${portNumber}`}
            variant="outlined"
            size="small"
          />
        )}
      </Box>
      
      <Typography variant="body2" sx={{ mb: 2, fontWeight: 500 }}>
        {config.description}
      </Typography>

      {(portNumber || customReason) && (
        <Box sx={{ mb: 2, p: 1, bgcolor: 'background.paper', borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
          <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
            Specific Risk Assessment:
          </Typography>
          <Typography variant="body2">
            {customReason || (portNumber ? getPortSpecificRisk(portNumber, serviceName) : '')}
          </Typography>
        </Box>
      )}

      <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
        Common {riskLevel} Risk Factors:
      </Typography>
      
      <List dense sx={{ py: 0 }}>
        {config.commonReasons.slice(0, 3).map((reason, idx) => (
          <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
            <ListItemIcon sx={{ minWidth: 20 }}>
              <Box 
                sx={{ 
                  width: 6, 
                  height: 6, 
                  borderRadius: '50%', 
                  backgroundColor: config.color 
                }} 
              />
            </ListItemIcon>
            <ListItemText 
              primary={reason}
              primaryTypographyProps={{ variant: 'body2', fontSize: '0.8rem' }}
            />
          </ListItem>
        ))}
      </List>

      <Box sx={{ mt: 2, pt: 1, borderTop: '1px solid', borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <SecurityIcon sx={{ fontSize: '1rem', mr: 0.5 }} />
            <Typography variant="caption">
              Risk Assessment Guide
            </Typography>
          </Box>
          <Link
            component="button"
            variant="caption"
            onClick={() => navigate('/risk-assessment')}
            sx={{ textDecoration: 'none' }}
          >
            Learn More →
          </Link>
        </Box>
      </Box>
    </Box>
  );

  return (
    <Tooltip
      title={tooltipContent}
      placement="top"
      arrow
      enterDelay={300}
      leaveDelay={100}
    >
      {children}
    </Tooltip>
  );
}