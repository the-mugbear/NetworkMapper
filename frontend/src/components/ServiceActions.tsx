import React from 'react';
import {
  Box,
  Chip,
  Link,
  Tooltip,
  IconButton,
  Typography,
  Popover,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Launch as LaunchIcon,
  Terminal as TerminalIcon,
  FileCopy as CopyIcon,
  Security as SecurityIcon,
  Lock as LockIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';

interface ServiceActionsProps {
  ipAddress: string;
  port: number;
  serviceName?: string;
  serviceProduct?: string;
  state: string;
}

interface ServiceAction {
  type: 'link' | 'command' | 'warning';
  label: string;
  value: string;
  description: string;
  icon: React.ReactNode;
  secure?: boolean;
}

const getServiceActions = (
  ip: string, 
  port: number, 
  service?: string, 
  product?: string
): ServiceAction[] => {
  const actions: ServiceAction[] = [];
  const serviceLower = service?.toLowerCase() || '';
  
  // HTTP Services
  if (port === 80 || serviceLower.includes('http') || serviceLower === 'www') {
    actions.push({
      type: 'link',
      label: 'Open HTTP',
      value: `http://${ip}:${port}`,
      description: 'Open web service in browser',
      icon: <LaunchIcon />,
    });
    actions.push({
      type: 'command',
      label: 'cURL Test',
      value: `curl -I http://${ip}:${port}`,
      description: 'Test HTTP headers with cURL',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'warning',
      label: 'Security Risk',
      value: 'HTTP transmits data in plaintext',
      description: 'Consider using HTTPS for sensitive data',
      icon: <WarningIcon />,
    });
  }
  
  // HTTPS Services
  if (port === 443 || serviceLower.includes('https') || serviceLower.includes('ssl') || serviceLower.includes('tls')) {
    actions.push({
      type: 'link',
      label: 'Open HTTPS',
      value: `https://${ip}:${port}`,
      description: 'Open secure web service in browser',
      icon: <LaunchIcon />,
      secure: true,
    });
    actions.push({
      type: 'command',
      label: 'SSL Test',
      value: `openssl s_client -connect ${ip}:${port} -servername ${ip}`,
      description: 'Test SSL/TLS certificate and configuration',
      icon: <SecurityIcon />,
    });
    actions.push({
      type: 'command',
      label: 'SSL Cert Info',
      value: `echo | openssl s_client -connect ${ip}:${port} -servername ${ip} 2>/dev/null | openssl x509 -noout -text`,
      description: 'View SSL certificate details',
      icon: <LockIcon />,
    });
  }
  
  // SSH Services
  if (port === 22 || serviceLower.includes('ssh')) {
    actions.push({
      type: 'command',
      label: 'SSH Connect',
      value: `ssh user@${ip}`,
      description: 'Connect via SSH (replace "user" with actual username)',
      icon: <TerminalIcon />,
      secure: true,
    });
    actions.push({
      type: 'command',
      label: 'SSH Key Scan',
      value: `ssh-keyscan -H ${ip}`,
      description: 'Get SSH host key fingerprints',
      icon: <SecurityIcon />,
    });
  }
  
  // FTP Services
  if (port === 21 || serviceLower.includes('ftp')) {
    actions.push({
      type: 'command',
      label: 'FTP Connect',
      value: `ftp ${ip}`,
      description: 'Connect to FTP server',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'command',
      label: 'Anonymous Test',
      value: `echo -e "anonymous\\nanonymous\\nls\\nquit" | ftp ${ip}`,
      description: 'Test for anonymous FTP access',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'warning',
      label: 'Security Risk',
      value: 'FTP transmits credentials in plaintext',
      description: 'Consider using SFTP or FTPS instead',
      icon: <WarningIcon />,
    });
  }
  
  // Telnet Services
  if (port === 23 || serviceLower.includes('telnet')) {
    actions.push({
      type: 'command',
      label: 'Telnet Connect',
      value: `telnet ${ip} ${port}`,
      description: 'Connect via Telnet',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'warning',
      label: 'Security Risk',
      value: 'Telnet transmits all data in plaintext',
      description: 'Replace with SSH for secure remote access',
      icon: <WarningIcon />,
    });
  }
  
  // Database Services
  if (port === 3306 || serviceLower.includes('mysql')) {
    actions.push({
      type: 'command',
      label: 'MySQL Connect',
      value: `mysql -h ${ip} -P ${port} -u username -p`,
      description: 'Connect to MySQL database',
      icon: <TerminalIcon />,
    });
  }
  
  if (port === 5432 || serviceLower.includes('postgresql')) {
    actions.push({
      type: 'command',
      label: 'PostgreSQL Connect',
      value: `psql -h ${ip} -p ${port} -U username -d database`,
      description: 'Connect to PostgreSQL database',
      icon: <TerminalIcon />,
    });
  }
  
  // SMTP Services
  if (port === 25 || serviceLower.includes('smtp')) {
    actions.push({
      type: 'command',
      label: 'SMTP Test',
      value: `telnet ${ip} ${port}`,
      description: 'Test SMTP server connectivity',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'command',
      label: 'SMTP Banner',
      value: `nc -nv ${ip} ${port}`,
      description: 'Get SMTP banner information',
      icon: <TerminalIcon />,
    });
  }
  
  // DNS Services
  if (port === 53 || serviceLower.includes('dns')) {
    actions.push({
      type: 'command',
      label: 'DNS Query',
      value: `nslookup google.com ${ip}`,
      description: 'Test DNS resolution',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'command',
      label: 'Zone Transfer',
      value: `dig @${ip} axfr domain.com`,
      description: 'Test for DNS zone transfer (replace domain.com)',
      icon: <TerminalIcon />,
    });
  }
  
  // SMB Services
  if (port === 445 || port === 139 || serviceLower.includes('smb') || serviceLower.includes('netbios')) {
    actions.push({
      type: 'command',
      label: 'SMB Shares',
      value: `smbclient -L ${ip} -N`,
      description: 'List SMB shares (anonymous)',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'command',
      label: 'SMB Enum',
      value: `enum4linux ${ip}`,
      description: 'Enumerate SMB information',
      icon: <TerminalIcon />,
    });
  }
  
  // SNMP Services
  if (port === 161 || serviceLower.includes('snmp')) {
    actions.push({
      type: 'command',
      label: 'SNMP Walk',
      value: `snmpwalk -c public -v1 ${ip}`,
      description: 'SNMP walk with community string "public"',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'warning',
      label: 'Default Community',
      value: 'Check for default community strings (public/private)',
      description: 'Default SNMP communities pose security risks',
      icon: <WarningIcon />,
    });
  }
  
  // RDP Services
  if (port === 3389 || serviceLower.includes('rdp') || serviceLower.includes('terminal-server')) {
    actions.push({
      type: 'command',
      label: 'RDP Connect',
      value: `rdesktop ${ip}:${port}`,
      description: 'Connect via Remote Desktop Protocol',
      icon: <TerminalIcon />,
    });
    actions.push({
      type: 'command',
      label: 'RDP Check',
      value: `nmap --script rdp-enum-encryption ${ip} -p ${port}`,
      description: 'Check RDP encryption level',
      icon: <SecurityIcon />,
    });
  }
  
  // General port testing
  actions.push({
    type: 'command',
    label: 'Port Test',
    value: `nc -zv ${ip} ${port}`,
    description: 'Test port connectivity with netcat',
    icon: <TerminalIcon />,
  });
  
  return actions;
};

export default function ServiceActions({ 
  ipAddress, 
  port, 
  serviceName, 
  serviceProduct, 
  state 
}: ServiceActionsProps) {
  const [anchorEl, setAnchorEl] = React.useState<HTMLElement | null>(null);
  const actions = getServiceActions(ipAddress, port, serviceName, serviceProduct);
  
  if (state !== 'open' || actions.length === 0) {
    return null;
  }
  
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  
  const handleClose = () => {
    setAnchorEl(null);
  };
  
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };
  
  const handleLinkClick = (url: string) => {
    window.open(url, '_blank', 'noopener,noreferrer');
  };
  
  const open = Boolean(anchorEl);
  
  return (
    <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
      <Tooltip title="Service actions and commands">
        <IconButton 
          size="small" 
          onClick={handleClick}
          sx={{ ml: 1 }}
        >
          <LaunchIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      
      <Popover
        open={open}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'left',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'left',
        }}
      >
        <Box sx={{ p: 2, maxWidth: 400 }}>
          <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 'bold' }}>
            Service Actions - {serviceName || 'Unknown'} ({port})
          </Typography>
          
          <List dense>
            {actions.map((action, index) => (
              <ListItem
                key={index}
                sx={{
                  px: 0,
                  py: 0.5,
                  cursor: action.type === 'warning' ? 'default' : 'pointer',
                }}
                onClick={() => {
                  if (action.type === 'link') {
                    handleLinkClick(action.value);
                  }
                }}
              >
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <Box sx={{ 
                    color: action.type === 'warning' ? 'warning.main' : 
                           action.secure ? 'success.main' : 'text.secondary' 
                  }}>
                    {action.icon}
                  </Box>
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {action.label}
                        {action.secure && (
                          <LockIcon sx={{ fontSize: '0.8rem', ml: 0.5, color: 'success.main' }} />
                        )}
                      </Typography>
                      {action.type === 'command' && (
                        <IconButton
                          size="small"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(action.value);
                          }}
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      )}
                    </Box>
                  }
                  secondary={
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        {action.description}
                      </Typography>
                      {action.type === 'command' && (
                        <Box
                          sx={{
                            mt: 0.5,
                            p: 1,
                            bgcolor: 'grey.100',
                            borderRadius: 0.5,
                            fontFamily: 'monospace',
                            fontSize: '0.75rem',
                            wordBreak: 'break-all',
                            border: '1px solid',
                            borderColor: 'grey.300',
                          }}
                        >
                          {action.value}
                        </Box>
                      )}
                      {action.type === 'warning' && (
                        <Chip
                          label={action.value}
                          size="small"
                          color="warning"
                          variant="outlined"
                          sx={{ mt: 0.5, fontSize: '0.7rem' }}
                        />
                      )}
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
          
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            Click commands to copy to clipboard. Links open in new tab.
          </Typography>
        </Box>
      </Popover>
    </Box>
  );
}