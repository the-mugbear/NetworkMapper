import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TextField,
  Paper,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  FormControlLabel,
  Switch,
} from '@mui/material';
import {
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { HostFilterOptions } from './HostFilters';
import { getToolReadyOutput } from '../services/api';

interface ToolReadyOutputProps {
  open: boolean;
  onClose: () => void;
  filters: HostFilterOptions;
}

const TOOL_FORMATS = [
  { value: 'ip-list', label: 'IP List', description: 'Simple list of IP addresses (one per line)' },
  { value: 'nmap', label: 'Nmap', description: 'Space-separated targets for Nmap' },
  { value: 'metasploit', label: 'Metasploit', description: 'RHOSTS format for Metasploit' },
  { value: 'masscan', label: 'Masscan', description: 'Comma-separated targets for Masscan' },
  { value: 'nuclei', label: 'Nuclei', description: 'URLs for web services, IPs for others' },
  { value: 'host-port', label: 'Host:Port', description: 'IP:PORT format for each open port' },
  { value: 'json', label: 'JSON', description: 'Detailed JSON with host information' },
];

export default function ToolReadyOutput({ open, onClose, filters }: ToolReadyOutputProps) {
  const [selectedFormat, setSelectedFormat] = useState('ip-list');
  const [includePorts, setIncludePorts] = useState(false);
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const generateOutput = async () => {
    setLoading(true);
    setError(null);
    setOutput('');

    try {
      // Build filter object for API call
      const apiFilters = {
        search: filters.search,
        state: filters.state,
        ports: filters.ports,
        services: filters.services,
        portStates: filters.portStates,
        hasOpenPorts: filters.hasOpenPorts,
        osFilter: filters.osFilter,
        subnets: filters.subnets,
        includePorts: includePorts,
      };

      const result = await getToolReadyOutput(selectedFormat, apiFilters);
      setOutput(result);
    } catch (err) {
      console.error('Error generating tool output:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate output');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  const downloadOutput = () => {
    const selectedFormatInfo = TOOL_FORMATS.find(f => f.value === selectedFormat);
    const extension = selectedFormat === 'json' ? 'json' : 'txt';
    const filename = `${selectedFormatInfo?.label.toLowerCase() || selectedFormat}-targets.${extension}`;
    
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const selectedFormatInfo = TOOL_FORMATS.find(f => f.value === selectedFormat);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center">
          <CodeIcon sx={{ mr: 1 }} />
          Tool-Ready Output Generator
        </Box>
      </DialogTitle>
      <DialogContent>
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Generate tool-ready output from filtered hosts for penetration testing tools.
          </Typography>
        </Box>

        <Box sx={{ mb: 3 }}>
          <FormControl fullWidth>
            <InputLabel>Output Format</InputLabel>
            <Select
              value={selectedFormat}
              label="Output Format"
              onChange={(e) => setSelectedFormat(e.target.value)}
            >
              {TOOL_FORMATS.map((format) => (
                <MenuItem key={format.value} value={format.value}>
                  <Box>
                    <Typography variant="body1">{format.label}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {format.description}
                    </Typography>
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        <Box sx={{ mb: 3 }}>
          <FormControlLabel
            control={
              <Switch
                checked={includePorts}
                onChange={(e) => setIncludePorts(e.target.checked)}
              />
            }
            label="Include detailed port information"
          />
        </Box>

        <Box sx={{ mb: 3 }}>
          <Button
            variant="contained"
            onClick={generateOutput}
            disabled={loading}
            fullWidth
            size="large"
          >
            {loading ? <CircularProgress size={24} /> : 'Generate Output'}
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {output && (
          <Box>
            <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
              <Typography variant="h6">
                Generated Output ({selectedFormatInfo?.label})
              </Typography>
              <Box>
                <Tooltip title={copied ? 'Copied!' : 'Copy to clipboard'}>
                  <IconButton onClick={copyToClipboard} size="small">
                    <CopyIcon />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Download as file">
                  <IconButton onClick={downloadOutput} size="small">
                    <DownloadIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>
            
            <Paper variant="outlined" sx={{ p: 2, maxHeight: '400px', overflow: 'auto' }}>
              <TextField
                multiline
                fullWidth
                value={output}
                InputProps={{
                  readOnly: true,
                  sx: {
                    fontFamily: 'monospace',
                    fontSize: '0.875rem',
                    '& .MuiInputBase-input': {
                      padding: 0,
                    },
                  },
                }}
                variant="standard"
                maxRows={20}
              />
            </Paper>
            
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {output.split('\n').filter(line => line.trim()).length} entries generated
            </Typography>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}