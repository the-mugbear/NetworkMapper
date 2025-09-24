import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  DialogContentText,
  Paper,
  Alert,
  CircularProgress,
  FormControlLabel,
  Checkbox,
  Divider,
  Tooltip,
  TextField,
  RadioGroup,
  Radio,
  FormControl,
  FormLabel,
  Collapse,
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  CloudUpload as UploadIcon,
} from '@mui/icons-material';
import { getScans, deleteScan, uploadFile, getIngestionJob } from '../services/api';
import type { Scan, IngestionJob } from '../services/api';

export default function Scans() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [scanToDelete, setScanToDelete] = useState<Scan | null>(null);
  
  // Upload state
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const [enrichDns, setEnrichDns] = useState(false);
  const [dnsServerType, setDnsServerType] = useState<'default' | 'custom'>('default');
  const [customDnsServer, setCustomDnsServer] = useState('');
  const [activeJobId, setActiveJobId] = useState<number | null>(null);
  const [activeJob, setActiveJob] = useState<IngestionJob | null>(null);

  const fetchScans = useCallback(async () => {
    try {
      const data = await getScans();
      setScans(data);
    } catch (error) {
      console.error('Error fetching scans:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Upload functionality
  const onDrop = async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    // Validate DNS configuration
    if (enrichDns && dnsServerType === 'custom' && customDnsServer.trim() === '') {
      setUploadError('Please enter a custom DNS server or select "Use system default DNS servers"');
      return;
    }

    setUploading(true);
    setUploadError(null);
    setUploadSuccess(null);

    try {
      const dnsConfig = enrichDns ? {
        enabled: true,
        server: dnsServerType === 'custom' ? customDnsServer.trim() : undefined
      } : { enabled: false };
      
      const result = await uploadFile(file, dnsConfig);
      setUploadSuccess(`File "${result.filename}" queued for processing…`);
      setActiveJobId(result.job_id);
      setActiveJob(null);
      setUploadError(null);
    } catch (err: any) {
      setUploadError(err.response?.data?.detail || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/xml': ['.xml', '.nessus'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/plain': ['.txt', '.gnmap']
    },
    multiple: false,
  });

  useEffect(() => {
    if (activeJobId === null) {
      return undefined;
    }

    let cancelled = false;
    let interval: ReturnType<typeof setInterval> | null = null;

    const pollJob = async () => {
      try {
        const job = await getIngestionJob(activeJobId);
        if (cancelled) return true;
        setActiveJob(job);

        if (job.status === 'completed') {
          setUploadSuccess(job.message || 'Scan processed successfully.');
          setUploadError(null);
          setActiveJobId(null);
          setTimeout(() => setUploadSuccess(null), 4000);
          fetchScans();
          return false;
        }

        if (job.status === 'failed') {
          setUploadError(job.error_message || 'Scan processing failed.');
          setUploadSuccess(null);
          setActiveJobId(null);
          return false;
        }

        return true;
      } catch (error) {
        if (!cancelled) {
          console.error('Failed to fetch ingestion job status:', error);
        }
        return true;
      }
    };

    pollJob().then((shouldContinue) => {
      if (cancelled || !shouldContinue) {
        return;
      }
      interval = setInterval(async () => {
        const keepGoing = await pollJob();
        if (!keepGoing && interval) {
          clearInterval(interval);
        }
      }, 4000);
    });

    return () => {
      cancelled = true;
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [activeJobId, fetchScans]);

  const groupedScans = scans.reduce<Record<string, Scan[]>>((acc, scan) => {
    const key = (scan.tool_name || scan.scan_type || 'Other').toUpperCase();
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(scan);
    return acc;
  }, {});

  const orderedToolGroups = Object.keys(groupedScans).sort((a, b) => a.localeCompare(b));

  const handleViewScan = (scanId: number) => {
    navigate(`/scans/${scanId}`);
  };

  const handleDeleteClick = (scan: Scan) => {
    setScanToDelete(scan);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (scanToDelete) {
      try {
        await deleteScan(scanToDelete.id);
        setScans(scans.filter(scan => scan.id !== scanToDelete.id));
      } catch (error) {
        console.error('Error deleting scan:', error);
      }
    }
    setDeleteDialogOpen(false);
    setScanToDelete(null);
  };

  const getStatusColor = (upHosts: number, totalHosts: number) => {
    if (totalHosts === 0) return 'default';
    const ratio = upHosts / totalHosts;
    if (ratio > 0.8) return 'success';
    if (ratio > 0.5) return 'warning';
    return 'error';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading scans...</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Scans
      </Typography>

      {/* Upload Section */}
      <Paper 
        {...getRootProps()} 
        sx={{
          p: 4,
          mb: 4,
          border: '2px dashed',
          borderColor: isDragActive ? 'primary.main' : 'grey.300',
          bgcolor: isDragActive ? 'action.hover' : 'background.paper',
          cursor: 'pointer',
          textAlign: 'center',
          '&:hover': {
            borderColor: 'primary.main',
            bgcolor: 'action.hover',
          }
        }}
      >
        <input {...getInputProps()} />
        <UploadIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
        <Typography variant="h6" gutterBottom>
          {isDragActive ? 'Drop the files here...' : 'Upload Scan Files'}
        </Typography>
        <Typography variant="body2" color="text.secondary" mb={2}>
          Drag and drop your scan files here, or click to select files
        </Typography>
        <Typography variant="caption" color="text.secondary" display="block" mb={2}>
          Supported formats: Nmap XML, Eyewitness JSON/CSV, Masscan XML/JSON/List, Nessus (.nessus)
        </Typography>
        
        <Box sx={{ mt: 2, p: 2, bgcolor: 'action.hover', borderRadius: 1, border: 1, borderColor: 'divider' }}>
          <Tooltip
            title={
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 1 }}>
                  DNS Data Enrichment
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  When enabled, this feature automatically enriches your scan results with additional DNS information:
                </Typography>
                <Typography variant="body2" component="div" sx={{ mb: 1 }}>
                  • <strong>Reverse DNS lookups:</strong> Converts IP addresses to hostnames
                </Typography>
                <Typography variant="body2" component="div" sx={{ mb: 1 }}>
                  • <strong>Forward DNS resolution:</strong> Validates and expands hostname data
                </Typography>
                <Typography variant="body2" component="div" sx={{ mb: 1 }}>
                  • <strong>Zone transfer attempts:</strong> Discovers additional subdomains (when permitted)
                </Typography>
                <Typography variant="body2" sx={{ mt: 1, fontStyle: 'italic' }}>
                  Note: DNS enrichment may increase processing time but provides more comprehensive host identification and network mapping.
                </Typography>
              </Box>
            }
            arrow
            placement="top"
          >
            <FormControlLabel
              control={
                <Checkbox
                  checked={enrichDns}
                  onChange={(e) => setEnrichDns(e.target.checked)}
                  onClick={(e) => e.stopPropagation()}
                />
              }
              label={
                <Box display="flex" alignItems="center" gap={1}>
                  <span>Enrich with DNS data</span>
                  <Typography 
                    variant="caption" 
                    color="text.secondary"
                    sx={{ 
                      fontStyle: 'italic',
                      textDecoration: 'underline dotted',
                      cursor: 'help'
                    }}
                  >
                    (hover for details)
                  </Typography>
                </Box>
              }
              onClick={(e) => e.stopPropagation()}
            />
          </Tooltip>

          <Collapse in={enrichDns}>
            <Box sx={{ mt: 2, ml: 4 }}>
              <FormControl component="fieldset">
                <FormLabel component="legend" sx={{ mb: 1, fontSize: '0.875rem' }}>
                  DNS Server Configuration
                </FormLabel>
                <RadioGroup
                  value={dnsServerType}
                  onChange={(e) => setDnsServerType(e.target.value as 'default' | 'custom')}
                  onClick={(e) => e.stopPropagation()}
                >
                  <FormControlLabel
                    value="default"
                    control={<Radio size="small" />}
                    label={
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                          Use system default DNS servers
                        </Typography>
                        <Typography variant="caption" color="text.primary" sx={{ opacity: 0.7 }}>
                          Uses the host system's configured DNS servers (typically 8.8.8.8, 1.1.1.1, or local DNS)
                        </Typography>
                      </Box>
                    }
                    onClick={(e) => e.stopPropagation()}
                  />
                  <FormControlLabel
                    value="custom"
                    control={<Radio size="small" />}
                    label={
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                          Use custom DNS server
                        </Typography>
                        <Typography variant="caption" color="text.primary" sx={{ opacity: 0.7 }}>
                          Specify a custom DNS server for lookups (e.g., internal DNS server)
                        </Typography>
                      </Box>
                    }
                    onClick={(e) => e.stopPropagation()}
                  />
                </RadioGroup>
              </FormControl>

              <Collapse in={dnsServerType === 'custom'}>
                <Box sx={{ mt: 2 }}>
                  <TextField
                    label="Custom DNS Server"
                    placeholder="e.g., 8.8.8.8, dns.company.com"
                    value={customDnsServer}
                    onChange={(e) => setCustomDnsServer(e.target.value)}
                    onClick={(e) => e.stopPropagation()}
                    size="small"
                    fullWidth
                    helperText="Enter IP address or hostname of the DNS server to use for lookups"
                    error={dnsServerType === 'custom' && customDnsServer.trim() === ''}
                  />
                </Box>
              </Collapse>
            </Box>
          </Collapse>
        </Box>
        
        {uploading && (
          <Box mt={2}>
            <CircularProgress size={24} />
            <Typography variant="body2" sx={{ mt: 1 }}>
              Uploading and processing...
            </Typography>
          </Box>
        )}
      </Paper>

      {/* Upload Status Messages */}
      {uploadError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {uploadError}
        </Alert>
      )}
      {uploadSuccess && (
        <Alert severity={activeJobId ? 'info' : 'success'} sx={{ mb: 2 }}>
          {uploadSuccess}
        </Alert>
      )}
      {activeJob && activeJob.status !== 'completed' && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <strong>Processing:</strong> {activeJob.original_filename}{' '}
          <Typography component="span" variant="body2" color="text.secondary">
            {activeJob.message || 'Working through the file in the background…'}
          </Typography>
        </Alert>
      )}

      <Divider sx={{ mb: 3 }} />

      {/* Scans List */}
      <Typography variant="h5" gutterBottom>
        Your Scans
      </Typography>

      {orderedToolGroups.length === 0 ? (
        <Box textAlign="center" py={4}>
          <Typography variant="body1" color="text.secondary">
            No scans uploaded yet. Use the upload area above to get started.
          </Typography>
        </Box>
      ) : (
        orderedToolGroups.map((group) => (
          <Box key={group} sx={{ mb: 4 }}>
            <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
              <Typography variant="h6" sx={{ textTransform: 'uppercase' }}>
                {group}
              </Typography>
              <Chip label={`${groupedScans[group].length} scans`} size="small" variant="outlined" />
            </Box>
            <Grid container spacing={2}>
              {groupedScans[group].map((scan) => (
                <Grid item xs={12} key={scan.id}>
                  <Card 
                    sx={{ 
                      '&:hover': { 
                        boxShadow: 4, 
                        cursor: 'pointer' 
                      } 
                    }}
                    onClick={() => handleViewScan(scan.id)}
                  >
                    <CardContent sx={{ py: 2 }}>
                  <Box>
                    {/* Top section - Main scan info and actions */}
                    <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                      <Box flex={1} mr={2}>
                        <Box display="flex" alignItems="center" gap={2} mb={1} flexWrap="wrap">
                          <Typography variant="h6" component="div" sx={{ wordBreak: 'break-all', minWidth: 0, flex: 1 }}>
                          {scan.filename}
                          </Typography>
                          {(scan.tool_name || scan.scan_type) && (
                            <Chip
                              label={scan.tool_name || scan.scan_type || 'Unknown'}
                              size="small"
                              color="primary"
                              variant="outlined"
                            />
                          )}
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          Uploaded: {new Date(scan.created_at).toLocaleString()}
                        </Typography>
                      </Box>

                      {/* Actions - Always visible */}
                      <Box display="flex" alignItems="center" gap={1} flexShrink={0}>
                        <Button
                          variant="contained"
                          color="primary"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewScan(scan.id);
                          }}
                          startIcon={<ViewIcon />}
                          size="small"
                          sx={{ minWidth: 'auto', px: 2 }}
                        >
                          <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                            View Details
                          </Box>
                          <Box component="span" sx={{ display: { xs: 'inline', sm: 'none' } }}>
                            View
                          </Box>
                        </Button>
                        <IconButton
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteClick(scan);
                          }}
                          color="error"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Box>
                    </Box>

                    {/* Bottom section - Statistics */}
                    <Box display="flex" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={2}>
                      <Box display="flex" alignItems="center" gap={3} flexWrap="wrap">
                        <Box textAlign="center">
                          <Typography variant="body2" color="text.secondary">
                            Hosts
                          </Typography>
                          <Typography variant="h6">
                            {scan.up_hosts}/{scan.total_hosts}
                          </Typography>
                        </Box>
                        <Box textAlign="center">
                          <Typography variant="body2" color="text.secondary">
                            Open Ports
                          </Typography>
                          <Typography variant="h6" color="success.main">
                            {scan.open_ports || 0}
                          </Typography>
                        </Box>
                        <Box textAlign="center">
                          <Typography variant="body2" color="text.secondary">
                            Total Ports
                          </Typography>
                          <Typography variant="h6">
                            {scan.total_ports || 0}
                          </Typography>
                        </Box>
                      </Box>
                      
                      {/* Status indicator */}
                      <Chip
                        label={scan.total_hosts > 0 ? `${((scan.up_hosts / scan.total_hosts) * 100).toFixed(0)}% hosts up` : 'No hosts'}
                        color={getStatusColor(scan.up_hosts, scan.total_hosts)}
                        size="small"
                      />
                    </Box>
                  </Box>
                </CardContent>
                </Card>
              </Grid>
              ))}
            </Grid>
          </Box>
        ))
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>Delete Scan</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete the scan "{scanToDelete?.filename}"?
            This action cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleDeleteConfirm} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
