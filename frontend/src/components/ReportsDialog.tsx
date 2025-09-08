import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Typography,
  CircularProgress,
  Alert,
  Chip,
} from '@mui/material';
import {
  Download as DownloadIcon,
  FileDownload as FileDownloadIcon,
  TableChart as TableChartIcon,
  Code as CodeIcon,
  Web as WebIcon,
} from '@mui/icons-material';
import { generateHostsReport } from '../services/api';
import { HostFilterOptions } from './HostFilters';

interface ReportsDialogProps {
  open: boolean;
  onClose: () => void;
  filters: HostFilterOptions;
  totalHosts: number;
}

const REPORT_FORMATS = [
  {
    value: 'csv',
    label: 'CSV (Comma Separated Values)',
    icon: <TableChartIcon />,
    description: 'Best for spreadsheet analysis',
    extension: 'csv'
  },
  {
    value: 'html',
    label: 'HTML Report',
    icon: <WebIcon />,
    description: 'Formatted web page with styling',
    extension: 'html'
  },
  {
    value: 'json',
    label: 'JSON Data',
    icon: <CodeIcon />,
    description: 'Machine-readable structured data',
    extension: 'json'
  }
];

const ReportsDialog: React.FC<ReportsDialogProps> = ({
  open,
  onClose,
  filters,
  totalHosts
}) => {
  const [selectedFormat, setSelectedFormat] = useState<'csv' | 'html' | 'json'>('csv');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    setError(null);
    
    try {
      // Convert filters to the format expected by the API
      const reportFilters = {
        scan_id: undefined, // We're not filtering by specific scan in hosts view
        state: filters.state,
        search: filters.search,
        ports: filters.ports?.join(','),
        services: filters.services?.join(','),
        port_states: filters.portStates?.join(','),
        has_open_ports: filters.hasOpenPorts,
        os_filter: filters.osFilter
      };

      await generateHostsReport(selectedFormat, reportFilters);
      onClose();
    } catch (err) {
      setError(`Failed to generate report: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const getActiveFiltersCount = () => {
    return [
      filters.search,
      filters.state,
      filters.ports?.length,
      filters.services?.length,
      filters.portStates?.length,
      filters.hasOpenPorts !== undefined,
      filters.osFilter
    ].filter(Boolean).length;
  };

  const renderActiveFilters = () => {
    const activeFilters = [];
    
    if (filters.search) {
      activeFilters.push(`Search: "${filters.search}"`);
    }
    if (filters.state) {
      activeFilters.push(`State: ${filters.state}`);
    }
    if (filters.ports?.length) {
      activeFilters.push(`Ports: ${filters.ports.join(', ')}`);
    }
    if (filters.services?.length) {
      activeFilters.push(`Services: ${filters.services.join(', ')}`);
    }
    if (filters.portStates?.length) {
      activeFilters.push(`Port States: ${filters.portStates.join(', ')}`);
    }
    if (filters.hasOpenPorts !== undefined) {
      activeFilters.push(`Has Open Ports: ${filters.hasOpenPorts ? 'Yes' : 'No'}`);
    }
    if (filters.osFilter) {
      activeFilters.push(`OS: ${filters.osFilter}`);
    }
    
    return activeFilters;
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={1}>
          <FileDownloadIcon />
          Generate Host Report
        </Box>
      </DialogTitle>
      
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        
        {/* Report Summary */}
        <Box mb={3}>
          <Typography variant="h6" gutterBottom>
            Report Summary
          </Typography>
          <Typography variant="body2" color="textSecondary" paragraph>
            This report will include approximately {totalHosts} hosts based on your current filters.
          </Typography>
          
          {getActiveFiltersCount() > 0 && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Active Filters ({getActiveFiltersCount()}):
              </Typography>
              <Box display="flex" flexWrap="wrap" gap={1}>
                {renderActiveFilters().map((filter, index) => (
                  <Chip
                    key={index}
                    label={filter}
                    size="small"
                    variant="outlined"
                    color="primary"
                  />
                ))}
              </Box>
            </Box>
          )}
        </Box>
        
        {/* Format Selection */}
        <FormControl fullWidth>
          <InputLabel>Report Format</InputLabel>
          <Select
            value={selectedFormat}
            label="Report Format"
            onChange={(e) => setSelectedFormat(e.target.value as 'csv' | 'html' | 'json')}
          >
            {REPORT_FORMATS.map((format) => (
              <MenuItem key={format.value} value={format.value}>
                <Box display="flex" alignItems="center" gap={1} width="100%">
                  {format.icon}
                  <Box>
                    <Typography>{format.label}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      {format.description}
                    </Typography>
                  </Box>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        
        {/* Format Description */}
        <Box mt={2} p={2} bgcolor="grey.50" borderRadius={1}>
          <Typography variant="body2">
            <strong>{REPORT_FORMATS.find(f => f.value === selectedFormat)?.label}:</strong>{' '}
            {REPORT_FORMATS.find(f => f.value === selectedFormat)?.description}
          </Typography>
        </Box>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose} disabled={isGenerating}>
          Cancel
        </Button>
        <Button
          onClick={handleGenerateReport}
          variant="contained"
          startIcon={isGenerating ? <CircularProgress size={20} /> : <DownloadIcon />}
          disabled={isGenerating}
        >
          {isGenerating ? 'Generating...' : 'Generate Report'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ReportsDialog;