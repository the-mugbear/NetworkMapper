import React from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';

const riskLevels = [
  {
    level: 'Critical',
    color: '#d32f2f',
    bgColor: '#ffebee',
    description: 'Immediate security threats requiring urgent attention',
    criteria: [
      'Open administrative ports (SSH, RDP, Telnet) exposed to public networks',
      'Unencrypted protocols handling sensitive data (HTTP, FTP, Telnet)',
      'Database services exposed without proper access controls',
      'Known vulnerable services with public exploits available',
    ],
    examples: [
      'SSH (22) open on public-facing servers',
      'Unencrypted HTTP (80) serving login pages',
      'MySQL (3306) accessible from external networks',
      'Telnet (23) services running on production systems',
    ],
  },
  {
    level: 'High',
    color: '#f57c00',
    bgColor: '#fff3e0',
    description: 'Significant security concerns that should be addressed promptly',
    criteria: [
      'Services running on non-standard ports that may indicate evasion',
      'Outdated protocols with known security limitations',
      'Services that commonly have misconfigurations',
      'High-value targets with elevated privilege access',
    ],
    examples: [
      'Web servers on non-standard ports (8080, 8443)',
      'SNMP (161) services with default community strings',
      'DNS (53) servers allowing zone transfers',
      'File sharing services (SMB, NFS) on business networks',
    ],
  },
  {
    level: 'Medium',
    color: '#fbc02d',
    bgColor: '#fffde7',
    description: 'Security issues that require attention but are not immediately critical',
    criteria: [
      'Common services that should be hardened or monitored',
      'Protocols that can leak information if misconfigured',
      'Services running with default configurations',
      'Network services that may indicate system compromise',
    ],
    examples: [
      'Web servers (80, 443) requiring security header review',
      'Email services (25, 110, 143) needing encryption verification',
      'VPN services requiring access control review',
      'Network time services that could be used for amplification',
    ],
  },
  {
    level: 'Low',
    color: '#388e3c',
    bgColor: '#e8f5e8',
    description: 'Services that are generally safe but should be documented',
    criteria: [
      'Standard services running on expected ports',
      'Properly configured encrypted services',
      'Services with appropriate access controls',
      'Development or testing services in isolated environments',
    ],
    examples: [
      'HTTPS (443) with proper SSL configuration',
      'Secure email services (993, 995) with encryption',
      'Internal DNS servers with proper zone restrictions',
      'Development servers on isolated network segments',
    ],
  },
];

const portRiskCategories = [
  {
    category: 'Administrative Access',
    ports: ['22 (SSH)', '3389 (RDP)', '23 (Telnet)', '5900 (VNC)'],
    riskLevel: 'Critical',
    reasoning: 'These ports provide direct system access and are prime targets for attackers.',
  },
  {
    category: 'Database Services',
    ports: ['3306 (MySQL)', '5432 (PostgreSQL)', '1433 (MSSQL)', '27017 (MongoDB)'],
    riskLevel: 'Critical',
    reasoning: 'Database exposure can lead to data breaches and system compromise.',
  },
  {
    category: 'Web Services',
    ports: ['80 (HTTP)', '443 (HTTPS)', '8080 (HTTP Alt)', '8443 (HTTPS Alt)'],
    riskLevel: 'Medium-High',
    reasoning: 'Web services are common attack vectors but may be legitimately exposed.',
  },
  {
    category: 'File Transfer',
    ports: ['21 (FTP)', '22 (SFTP)', '445 (SMB)', '2049 (NFS)'],
    riskLevel: 'High',
    reasoning: 'File transfer services can expose sensitive data if misconfigured.',
  },
];

export default function RiskAssessment() {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Risk Assessment Documentation
      </Typography>
      
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          NetworkMapper uses an automated risk assessment system to help prioritize security findings. 
          This page explains how risks are calculated and what each level means for your network security.
        </Typography>
      </Alert>

      <Grid container spacing={3}>
        {/* Risk Level Overview */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
              <SecurityIcon sx={{ mr: 1 }} />
              Risk Level Overview
            </Typography>
            
            <Grid container spacing={2}>
              {riskLevels.map((risk) => (
                <Grid item xs={12} md={6} key={risk.level}>
                  <Card sx={{ height: '100%', border: `2px solid ${risk.color}` }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                        <Chip 
                          label={risk.level}
                          sx={{ 
                            backgroundColor: risk.color,
                            color: 'white',
                            fontWeight: 'bold',
                            mr: 1
                          }}
                        />
                        {risk.level === 'Critical' && <ErrorIcon sx={{ color: risk.color }} />}
                        {risk.level === 'High' && <WarningIcon sx={{ color: risk.color }} />}
                        {risk.level === 'Medium' && <InfoIcon sx={{ color: risk.color }} />}
                        {risk.level === 'Low' && <CheckCircleIcon sx={{ color: risk.color }} />}
                      </Box>
                      
                      <Typography variant="body1" sx={{ mb: 2, fontWeight: 500 }}>
                        {risk.description}
                      </Typography>
                      
                      <Typography variant="body2" sx={{ mb: 1, fontWeight: 500 }}>
                        Risk Criteria:
                      </Typography>
                      <List dense>
                        {risk.criteria.map((criteria, idx) => (
                          <ListItem key={idx} sx={{ py: 0.5 }}>
                            <ListItemText 
                              primary={criteria}
                              primaryTypographyProps={{ variant: 'body2' }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Grid>

        {/* Port Risk Categories */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h5" gutterBottom>
              Port Risk Categories
            </Typography>
            
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell><strong>Category</strong></TableCell>
                    <TableCell><strong>Common Ports</strong></TableCell>
                    <TableCell><strong>Risk Level</strong></TableCell>
                    <TableCell><strong>Reasoning</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {portRiskCategories.map((category, idx) => (
                    <TableRow key={idx}>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {category.category}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {category.ports.map((port, portIdx) => (
                            <Chip 
                              key={portIdx}
                              label={port}
                              size="small"
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={category.riskLevel}
                          size="small"
                          color={
                            category.riskLevel === 'Critical' ? 'error' :
                            category.riskLevel === 'High' ? 'warning' :
                            category.riskLevel === 'Medium-High' ? 'warning' : 'success'
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {category.reasoning}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Common Ports and Services */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h5" gutterBottom>
              Common Ports and Services
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell><strong>Port</strong></TableCell>
                    <TableCell><strong>Service</strong></TableCell>
                    <TableCell><strong>Description</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell>21</TableCell>
                    <TableCell>FTP</TableCell>
                    <TableCell>File Transfer Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>22</TableCell>
                    <TableCell>SSH</TableCell>
                    <TableCell>Secure Shell</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>23</TableCell>
                    <TableCell>Telnet</TableCell>
                    <TableCell>Remote terminal protocol (insecure)</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>25</TableCell>
                    <TableCell>SMTP</TableCell>
                    <TableCell>Simple Mail Transfer Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>53</TableCell>
                    <TableCell>DNS</TableCell>
                    <TableCell>Domain Name System</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>80</TableCell>
                    <TableCell>HTTP</TableCell>
                    <TableCell>Hypertext Transfer Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>110</TableCell>
                    <TableCell>POP3</TableCell>
                    <TableCell>Post Office Protocol version 3</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>143</TableCell>
                    <TableCell>IMAP</TableCell>
                    <TableCell>Internet Message Access Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>443</TableCell>
                    <TableCell>HTTPS</TableCell>
                    <TableCell>HTTP Secure</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>445</TableCell>
                    <TableCell>SMB</TableCell>
                    <TableCell>Server Message Block</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>3306</TableCell>
                    <TableCell>MySQL</TableCell>
                    <TableCell>MySQL database</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>3389</TableCell>
                    <TableCell>RDP</TableCell>
                    <TableCell>Remote Desktop Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>5432</TableCell>
                    <TableCell>PostgreSQL</TableCell>
                    <TableCell>PostgreSQL database</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>8080</TableCell>
                    <TableCell>HTTP-alt</TableCell>
                    <TableCell>Alternate HTTP port</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>688</TableCell>
                    <TableCell>Kerberos</TableCell>
                    <TableCell>Network authentication protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>389</TableCell>
                    <TableCell>LDAP</TableCell>
                    <TableCell>Lightweight Directory Access Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>636</TableCell>
                    <TableCell>LDAPS</TableCell>
                    <TableCell>LDAP over SSL</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>135</TableCell>
                    <TableCell>MS-RPC</TableCell>
                    <TableCell>Microsoft Remote Procedure Call</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>139</TableCell>
                    <TableCell>NetBIOS</TableCell>
                    <TableCell>NetBIOS Session Service</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>161</TableCell>
                    <TableCell>SNMP</TableCell>
                    <TableCell>Simple Network Management Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>623</TableCell>
                    <TableCell>IPMI</TableCell>
                    <TableCell>Intelligent Platform Management Interface</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>1723</TableCell>
                    <TableCell>PPTP</TableCell>
                    <TableCell>Point-to-Point Tunneling Protocol</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>1812</TableCell>
                    <TableCell>RADIUS</TableCell>
                    <TableCell>Remote Authentication Dial-In User Service</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>5900</TableCell>
                    <TableCell>VNC</TableCell>
                    <TableCell>Virtual Network Computing</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>8443</TableCell>
                    <TableCell>HTTPS-alt</TableCell>
                    <TableCell>Alternate HTTPS port</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Detailed Risk Examples */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h5" gutterBottom>
              Detailed Risk Examples
            </Typography>
            
            {riskLevels.map((risk, idx) => (
              <Accordion key={idx}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                    <Chip 
                      label={risk.level}
                      sx={{ 
                        backgroundColor: risk.color,
                        color: 'white',
                        mr: 2
                      }}
                    />
                    <Typography variant="h6">
                      {risk.level} Risk Examples
                    </Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    <strong>Common scenarios that result in {risk.level.toLowerCase()} risk ratings:</strong>
                  </Typography>
                  <List>
                    {risk.examples.map((example, exampleIdx) => (
                      <ListItem key={exampleIdx}>
                        <ListItemIcon>
                          <Box 
                            sx={{ 
                              width: 8, 
                              height: 8, 
                              borderRadius: '50%', 
                              backgroundColor: risk.color 
                            }} 
                          />
                        </ListItemIcon>
                        <ListItemText primary={example} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>
        </Grid>

        {/* Risk Calculation Methodology */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h5" gutterBottom>
              Risk Calculation Methodology
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2 }}>
              NetworkMapper calculates risk scores based on several factors:
            </Typography>
            
            <List>
              <ListItem>
                <ListItemIcon><SecurityIcon /></ListItemIcon>
                <ListItemText 
                  primary="Port Classification" 
                  secondary="Each port is classified based on its common usage and security implications"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><SecurityIcon /></ListItemIcon>
                <ListItemText 
                  primary="Service Detection" 
                  secondary="Services are analyzed for known vulnerabilities and misconfigurations"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><SecurityIcon /></ListItemIcon>
                <ListItemText 
                  primary="Network Context" 
                  secondary="Location in network topology affects risk (internal vs external facing)"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><SecurityIcon /></ListItemIcon>
                <ListItemText 
                  primary="Service State" 
                  secondary="Open ports receive higher risk scores than filtered or closed ports"
                />
              </ListItem>
            </List>
            
            <Alert severity="warning" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Important:</strong> Risk assessments are automated suggestions based on common security practices. 
                Always consider your specific network requirements and security policies when making decisions.
              </Typography>
            </Alert>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}