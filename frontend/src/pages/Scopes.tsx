import React, { useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Box,
  Typography,
  Button,
  Alert,
  Card,
  CardContent,
  TextField,
  CircularProgress,
  Chip,
  Grid,
  IconButton,
  Divider,
  Paper,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
} from '@mui/material';
import {
  Download as ExportIcon,
  Refresh as CorrelateIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  CloudUpload,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { 
  getScopes, 
  deleteScope, 
  uploadSubnetFile, 
  correlateAllHosts,
  exportScopeReport,
  exportOutOfScopeReport,
  ScopeSummary,
  ScopeCoverageSummary,
  getScopeCoverage,
} from '../services/api';
import ExportDialog from '../components/ExportDialog';

const Scopes: React.FC = () => {
  const navigate = useNavigate();
  const [scopes, setScopes] = useState<ScopeSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [coverage, setCoverage] = useState<ScopeCoverageSummary | null>(null);

  // Upload state
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [scopeName, setScopeName] = useState('');
  const [scopeDescription, setScopeDescription] = useState('');

  // Export dialog state
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [exportDialogType, setExportDialogType] = useState<'scope' | 'out-of-scope'>('scope');
  const [exportItemId, setExportItemId] = useState<number | undefined>();
  const [exportItemName, setExportItemName] = useState<string>('');

  useEffect(() => {
    loadData(true);
  }, []);

  const loadData = async (showSpinner = false) => {
    if (showSpinner) {
      setLoading(true);
    }
    try {
      const [scopeData, coverageData] = await Promise.all([
        getScopes(),
        getScopeCoverage(),
      ]);
      setScopes(scopeData);
      setCoverage(coverageData);
      setError(null);
    } catch (err) {
      setError('Failed to load scope data');
      console.error('Error loading scope data:', err);
    } finally {
      if (showSpinner) {
        setLoading(false);
      }
    }
  };

  // Upload functionality
  const onDrop = async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    // Validate scope name
    if (!scopeName.trim()) {
      setUploadError('Please enter a scope name before uploading');
      return;
    }

    setUploading(true);
    setUploadError(null);
    setStatusMessage(null);

    try {
      const response = await uploadSubnetFile(file, scopeName.trim(), scopeDescription.trim() || undefined);
      setStatusMessage(response.message || `Subnet file "${file.name}" uploaded successfully!`);

      // Reset form
      setScopeName('');
      setScopeDescription('');

      // Reload scopes
      await loadData();

      // Clear success message after 3 seconds
      setTimeout(() => {
        setStatusMessage(null);
      }, 3000);
    } catch (err: any) {
      setUploadError(err.response?.data?.detail || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.txt'],
      'text/csv': ['.csv']
    },
    multiple: false,
  });

  const handleDelete = async (scopeId: number, scopeName: string) => {
    if (window.confirm(`Are you sure you want to delete the scope "${scopeName}"? This will also delete all its subnets and mappings.`)) {
      try {
        await deleteScope(scopeId);
        await loadData();
      } catch (err) {
        setError('Failed to delete scope');
        console.error('Error deleting scope:', err);
      }
    }
  };

  const handleCorrelateAll = async () => {
    if (window.confirm('This will correlate all existing hosts to their respective subnets. This may take some time. Continue?')) {
      try {
        setCorrelating(true);
        setError(null);
        
        const result = await correlateAllHosts();
        setError(null);
        if (result?.message) {
          setStatusMessage(result.message);
          setTimeout(() => setStatusMessage(null), 3000);
        }
        await loadData();

      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to correlate hosts to subnets');
        console.error('Error correlating hosts:', err);
      } finally {
        setCorrelating(false);
      }
    }
  };

  const handleOpenScopeExport = (scopeId: number, scopeName: string) => {
    setExportDialogType('scope');
    setExportItemId(scopeId);
    setExportItemName(scopeName);
    setShowExportDialog(true);
  };

  const handleOpenOutOfScopeExport = () => {
    setExportDialogType('out-of-scope');
    setExportItemId(undefined);
    setExportItemName('Out-of-Scope Findings');
    setShowExportDialog(true);
  };

  const handleCloseExportDialog = () => {
    setShowExportDialog(false);
    setExportItemId(undefined);
    setExportItemName('');
  };

  const coverageChipColor = (() => {
    if (!coverage) return 'default' as const;
    if (coverage.coverage_percentage >= 90) return 'success' as const;
    if (coverage.coverage_percentage >= 50) return 'warning' as const;
    if (coverage.coverage_percentage > 0) return 'error' as const;
    return 'default' as const;
  })();

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Scopes & Subnets
      </Typography>

      {/* Header Actions */}
      <Box display="flex" justifyContent="flex-end" alignItems="center" mb={3} gap={2}>
        <Button
          variant="contained"
          color="success"
          startIcon={correlating ? <CircularProgress size={20} color="inherit" /> : <CorrelateIcon />}
          onClick={handleCorrelateAll}
          disabled={correlating}
        >
          {correlating ? 'Correlating...' : 'Correlate All Hosts'}
        </Button>
        <Button
          variant="contained"
          color="error"
          startIcon={<ExportIcon />}
          onClick={handleOpenOutOfScopeExport}
        >
          Export Out-of-Scope
        </Button>
      </Box>

      {coverage && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">Scope Coverage</Typography>
              <Chip
                label={`${coverage.coverage_percentage.toFixed(1)}% covered`}
                color={coverageChipColor}
                variant={coverageChipColor === 'default' ? 'outlined' : 'filled'}
                size="small"
              />
            </Box>

            <Grid container spacing={2} mb={coverage.out_of_scope_hosts > 0 ? 2 : 0}>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h5" color="primary">
                    {coverage.total_hosts}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Hosts
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h5" color="success.main">
                    {coverage.scoped_hosts}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    In Scope
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h5" color={coverage.out_of_scope_hosts ? 'error.main' : 'text.secondary'}>
                    {coverage.out_of_scope_hosts}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Out of Scope
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h5" color="text.secondary">
                    {coverage.total_subnets}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Subnets Defined
                  </Typography>
                </Box>
              </Grid>
            </Grid>

            {coverage.out_of_scope_hosts > 0 ? (
              <Box>
                <Typography variant="subtitle1" gutterBottom>
                  Hosts discovered outside configured scopes
                </Typography>
                <List dense sx={{ maxHeight: 260, overflow: 'auto' }}>
                  {coverage.recent_out_of_scope_hosts.map((host) => {
                    const lastSeen = host.last_seen ? new Date(host.last_seen).toLocaleString() : 'Unknown';
                    const scanLabel = host.last_scan_filename
                      ? host.last_scan_filename
                      : host.last_scan_id
                      ? `Scan #${host.last_scan_id}`
                      : null;

                    return (
                      <ListItem disablePadding key={`oos-${host.host_id}`}>
                        <ListItemButton onClick={() => navigate(`/hosts/${host.host_id}`)}>
                          <ListItemText
                            primary={
                              <Box display="flex" justifyContent="space-between" alignItems="center" gap={1}>
                                <Typography variant="subtitle2" fontFamily="monospace">
                                  {host.ip_address}
                                </Typography>
                                {host.hostname && (
                                  <Typography
                                    variant="body2"
                                    color="text.secondary"
                                    noWrap
                                    sx={{ maxWidth: { xs: '50%', md: '60%' } }}
                                  >
                                    {host.hostname}
                                  </Typography>
                                )}
                              </Box>
                            }
                            secondary={
                              <Typography variant="body2" color="text.secondary">
                                Last seen {lastSeen}
                                {scanLabel && ` · ${scanLabel}`}
                              </Typography>
                            }
                          />
                        </ListItemButton>
                      </ListItem>
                    );
                  })}
                </List>
                {coverage.out_of_scope_hosts > coverage.recent_out_of_scope_hosts.length && (
                  <Typography variant="caption" color="text.secondary">
                    Showing the most recent {coverage.recent_out_of_scope_hosts.length} of {coverage.out_of_scope_hosts} hosts.
                  </Typography>
                )}
                <Button
                  size="small"
                  sx={{ mt: 1 }}
                  onClick={() => navigate('/hosts?out_of_scope=true')}
                >
                  View all out-of-scope hosts
                </Button>
              </Box>
            ) : coverage.has_scope_configuration ? (
              <Alert severity="success" sx={{ mt: 1 }}>
                All hosts currently map to defined scopes.
              </Alert>
            ) : (
              <Alert severity="info" sx={{ mt: 1 }}>
                No subnet scopes configured yet. Upload a subnet file to begin tracking out-of-scope hosts.
              </Alert>
            )}
          </CardContent>
        </Card>
      )}

      {/* Upload Section */}
      <Paper sx={{ p: 4, mb: 4 }}>
        <Grid container spacing={3} alignItems="stretch">
          <Grid item xs={12} md={4}>
            <Typography variant="h6" gutterBottom>
              Scope Details
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Provide a name and optional description before uploading your subnet file.
            </Typography>
            <TextField
              label="Scope Name"
              placeholder="e.g., Internal Network, DMZ, External Ranges"
              value={scopeName}
              onChange={(e) => setScopeName(e.target.value)}
              fullWidth
              required
              helperText="Required before selecting a subnet file"
              sx={{ mb: 2 }}
            />
            <TextField
              label="Description"
              placeholder="Optional description of this scope's purpose or coverage"
              value={scopeDescription}
              onChange={(e) => setScopeDescription(e.target.value)}
              fullWidth
              multiline
              minRows={3}
              helperText="Optional context for teammates"
            />
          </Grid>
          <Grid item xs={12} md={8}>
            <Box
              {...getRootProps()}
              sx={{
                p: 4,
                borderRadius: 2,
                border: '2px dashed',
                borderColor: uploading
                  ? 'grey.300'
                  : isDragActive
                  ? 'primary.main'
                  : 'grey.300',
                bgcolor: isDragActive ? 'action.hover' : 'background.paper',
                cursor: uploading ? 'not-allowed' : 'pointer',
                opacity: uploading ? 0.6 : 1,
                textAlign: 'center',
                transition: 'border-color 0.2s ease',
                '&:hover': uploading
                  ? {}
                  : {
                      borderColor: 'primary.main',
                      bgcolor: 'action.hover',
                    },
              }}
            >
              <input {...getInputProps()} disabled={uploading} />
              <CloudUpload sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                {isDragActive ? 'Drop the subnet files here…' : 'Upload Subnet Files'}
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={2}>
                Drag and drop your subnet files here, or click to select files.
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block" mb={1.5}>
                Supported formats: .txt, .csv (one subnet per line, e.g., 192.168.1.0/24)
              </Typography>
              {!scopeName.trim() && (
                <Typography variant="caption" color="error">
                  Enter a scope name before uploading to flag out-of-scope hosts correctly.
                </Typography>
              )}
            </Box>
            {uploading && (
              <Box mt={2} display="flex" flexDirection="column" alignItems="center">
                <CircularProgress size={24} />
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Uploading and processing...
                </Typography>
              </Box>
            )}
          </Grid>
        </Grid>
      </Paper>

      {/* Upload Status Messages */}
      {uploadError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {uploadError}
        </Alert>
      )}
      {statusMessage && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {statusMessage}
        </Alert>
      )}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Divider sx={{ mb: 3 }} />

      {/* Scopes List */}
      <Typography variant="h5" gutterBottom>
        Your Scopes
      </Typography>

      {scopes.length === 0 ? (
        <Box textAlign="center" py={4}>
          <Typography variant="body1" color="text.secondary">
            No scopes uploaded yet. Use the upload area above to get started.
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={2}>
          {scopes.map((scope) => (
            <Grid item xs={12} key={scope.id}>
              <Card
                sx={{
                  '&:hover': {
                    boxShadow: 4,
                    cursor: 'pointer'
                  }
                }}
                onClick={() => navigate(`/scopes/${scope.id}`)}
              >
                <CardContent sx={{ py: 2 }}>
                  <Box>
                    {/* Top section - Main scope info and actions */}
                    <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                      <Box flex={1} mr={2}>
                        <Box display="flex" alignItems="center" gap={2} mb={1} flexWrap="wrap">
                          <Typography variant="h6" component="div" sx={{ wordBreak: 'break-all', minWidth: 0, flex: 1 }}>
                            {scope.name}
                          </Typography>
                          <Chip
                            label={`${scope.subnet_count} subnets`}
                            size="small"
                            color="primary"
                            variant="outlined"
                          />
                        </Box>
                        {scope.description && (
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {scope.description}
                          </Typography>
                        )}
                        <Typography variant="body2" color="text.secondary">
                          Created: {new Date(scope.created_at).toLocaleString()}
                        </Typography>
                      </Box>

                      {/* Actions - Always visible */}
                      <Box display="flex" alignItems="center" gap={1} flexShrink={0}>
                        <Button
                          variant="contained"
                          color="primary"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/scopes/${scope.id}`);
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
                        <Button
                          variant="outlined"
                          color="success"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenScopeExport(scope.id, scope.name);
                          }}
                          startIcon={<ExportIcon />}
                          size="small"
                          sx={{ minWidth: 'auto', px: 2 }}
                        >
                          <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                            Export
                          </Box>
                          <Box component="span" sx={{ display: { xs: 'inline', sm: 'none' } }}>
                            Export
                          </Box>
                        </Button>
                        <IconButton
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDelete(scope.id, scope.name);
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
                            Subnets
                          </Typography>
                          <Typography variant="h6">
                            {scope.subnet_count}
                          </Typography>
                        </Box>
                        <Box textAlign="center">
                          <Typography variant="body2" color="text.secondary">
                            Status
                          </Typography>
                          <Typography variant="h6" color="success.main">
                            Active
                          </Typography>
                        </Box>
                      </Box>

                      {/* Status indicator */}
                      <Chip
                        label={scope.subnet_count > 0 ? `${scope.subnet_count} subnet${scope.subnet_count !== 1 ? 's' : ''} defined` : 'No subnets'}
                        color={scope.subnet_count > 0 ? 'success' : 'default'}
                        size="small"
                      />
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Export Dialog */}
      <ExportDialog
        open={showExportDialog}
        onClose={handleCloseExportDialog}
        title={exportDialogType === 'scope' ? 'Scope Report' : 'Out-of-Scope Report'}
        exportType={exportDialogType}
        itemId={exportItemId}
        itemName={exportItemName}
      />
    </Box>
  );
};

export default Scopes;
