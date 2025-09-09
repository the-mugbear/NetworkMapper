import React from 'react';
import {
  Tooltip,
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Info as InfoIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';

interface FilterTooltipProps {
  children: React.ReactElement;
  filterType: 'state' | 'ports' | 'services' | 'port_states' | 'has_open_ports' | 'os_filter' | 'risk_level' | 'subnet';
  customExplanation?: string;
}

const filterExplanations = {
  state: {
    title: 'Host State Filter',
    description: 'Filter hosts based on their operational status during the scan',
    options: [
      { value: 'Up', description: 'Hosts that responded to ping or port probes' },
      { value: 'Down', description: 'Hosts that did not respond to any probes' },
      { value: 'Unknown', description: 'Hosts with undetermined status' },
    ],
    note: 'Host state is determined by network responsiveness during scanning',
  },
  ports: {
    title: 'Port Number Filter',
    description: 'Find hosts with specific ports open, filtered, or closed',
    options: [
      { value: '22,80,443', description: 'Multiple ports separated by commas' },
      { value: '8000-9000', description: 'Port ranges using dash notation' },
      { value: '80', description: 'Single port number' },
    ],
    note: 'Supports individual ports, ranges, and comma-separated lists',
  },
  services: {
    title: 'Service Name Filter',
    description: 'Filter by detected service names or applications',
    options: [
      { value: 'ssh,http,https', description: 'Common service names' },
      { value: 'mysql,postgresql', description: 'Database services' },
      { value: 'apache,nginx', description: 'Web server applications' },
    ],
    note: 'Service detection depends on scan type and probe responses',
  },
  port_states: {
    title: 'Port State Filter',
    description: 'Filter ports by their connection state during scanning',
    options: [
      { value: 'open', description: 'Ports accepting connections' },
      { value: 'closed', description: 'Ports refusing connections' },
      { value: 'filtered', description: 'Ports blocked by firewall/filter' },
    ],
    note: 'Port states help identify firewall configurations and service availability',
  },
  has_open_ports: {
    title: 'Open Ports Filter',
    description: 'Show only hosts that have at least one open port',
    options: [
      { value: 'true', description: 'Hosts with one or more open ports' },
      { value: 'false', description: 'Hosts with no open ports detected' },
    ],
    note: 'Useful for focusing on hosts that are actively serving network services',
  },
  os_filter: {
    title: 'Operating System Filter',
    description: 'Filter hosts by detected or identified operating system',
    options: [
      { value: 'Linux,Windows,macOS', description: 'Common operating system families' },
      { value: 'Ubuntu,CentOS,Windows 10', description: 'Specific OS versions' },
      { value: 'Unix,BSD', description: 'Unix-like operating systems' },
    ],
    note: 'OS detection accuracy varies based on scan techniques and host configuration',
  },
  risk_level: {
    title: 'Risk Level Filter',
    description: 'Filter by automatically calculated security risk assessment',
    options: [
      { value: 'Critical', description: 'Immediate security threats requiring urgent attention' },
      { value: 'High', description: 'Significant security concerns needing prompt review' },
      { value: 'Medium', description: 'Security issues requiring attention but not critical' },
      { value: 'Low', description: 'Generally safe services that should be documented' },
    ],
    note: 'Risk levels are calculated based on service exposure and security implications',
  },
  subnet: {
    title: 'Subnet Filter',
    description: 'Filter hosts by their network subnet or IP address range',
    options: [
      { value: '192.168.1.0/24', description: 'CIDR notation for subnet ranges' },
      { value: '10.0.0.0/8', description: 'Large private network ranges' },
      { value: '172.16.0.0/12', description: 'Private address space subnets' },
    ],
    note: 'Helps organize findings by network segments and security zones',
  },
};

export default function FilterTooltip({ 
  children, 
  filterType, 
  customExplanation 
}: FilterTooltipProps) {
  const config = filterExplanations[filterType];
  
  if (!config && !customExplanation) {
    return children;
  }

  const tooltipContent = (
    <Box sx={{ maxWidth: 350, p: 1 }}>
      {config && (
        <>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <FilterIcon sx={{ mr: 1, fontSize: '1.2rem' }} />
            <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
              {config.title}
            </Typography>
          </Box>
          
          <Typography variant="body2" sx={{ mb: 2 }}>
            {config.description}
          </Typography>

          {config.options && (
            <>
              <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
                Example Values:
              </Typography>
              
              <List dense sx={{ py: 0, mb: 2 }}>
                {config.options.map((option, idx) => (
                  <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <Box 
                        sx={{ 
                          width: 6, 
                          height: 6, 
                          borderRadius: '50%', 
                          backgroundColor: 'primary.main' 
                        }} 
                      />
                    </ListItemIcon>
                    <ListItemText>
                      <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                        <strong>{option.value}:</strong> {option.description}
                      </Typography>
                    </ListItemText>
                  </ListItem>
                ))}
              </List>
            </>
          )}

          {config.note && (
            <Box sx={{ 
              mt: 1, 
              p: 1, 
              bgcolor: 'action.hover', 
              borderRadius: 1,
              border: '1px solid',
              borderColor: 'divider'
            }}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                <InfoIcon sx={{ fontSize: '1rem', mr: 0.5, mt: 0.1 }} />
                <Typography variant="caption">
                  {config.note}
                </Typography>
              </Box>
            </Box>
          )}
        </>
      )}

      {customExplanation && (
        <Typography variant="body2">
          {customExplanation}
        </Typography>
      )}
    </Box>
  );

  return (
    <Tooltip
      title={tooltipContent}
      placement="top"
      arrow
      enterDelay={500}
      leaveDelay={100}
    >
      {children}
    </Tooltip>
  );
}