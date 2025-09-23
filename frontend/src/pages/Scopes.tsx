import React, { useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Box,
  Typography,
  Button,
  Alert,
  Card,
  CardContent,
  CardActions,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControlLabel,
  Checkbox,
  CircularProgress,
  Chip,
  Grid,
  IconButton,
  Divider,
  LinearProgress,
  Paper,
  Tooltip,
  Collapse,
  FormControl,
  FormLabel,
  RadioGroup,
  Radio
} from '@mui/material';
import {
  Upload as UploadIcon,
  Download as ExportIcon,
  Refresh as CorrelateIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  CloudUpload,
  Close as CloseIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { 
  getScopes, 
  deleteScope, 
  uploadSubnetFile, 
  correlateAllHosts,
  exportScopeReport,
  exportOutOfScopeReport,
  ScopeSummary 
} from '../services/api';
import ExportDialog from '../components/ExportDialog';

const Scopes: React.FC = () => {
  const navigate = useNavigate();
  const [scopes, setScopes] = useState<ScopeSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [correlating, setCorrelating] = useState(false);

  // Upload state
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const [scopeName, setScopeName] = useState('');
  const [scopeDescription, setScopeDescription] = useState('');
  const [showUploadOptions, setShowUploadOptions] = useState(false);

  // Export dialog state
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [exportDialogType, setExportDialogType] = useState<'scope' | 'out-of-scope'>('scope');
  const [exportItemId, setExportItemId] = useState<number | undefined>();
  const [exportItemName, setExportItemName] = useState<string>('');

  useEffect(() => {
    loadScopes();
  }, []);

  const loadScopes = async () => {
    try {
      setLoading(true);
      const data = await getScopes();
      setScopes(data);
      setError(null);
    } catch (err) {
      setError('Failed to load scopes');
      console.error('Error loading scopes:', err);
    } finally {
      setLoading(false);
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
    setUploadSuccess(null);

    try {
      await uploadSubnetFile(file, scopeName.trim(), scopeDescription.trim() || undefined);
      setUploadSuccess(`Subnet file "${file.name}" uploaded successfully!`);

      // Reset form
      setScopeName('');
      setScopeDescription('');
      setShowUploadOptions(false);

      // Reload scopes
      await loadScopes();

      // Clear success message after 3 seconds
      setTimeout(() => {
        setUploadSuccess(null);
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
        await loadScopes();
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
        setError(null); // Clear any errors and show success
        
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
        <CloudUpload sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
        <Typography variant="h6" gutterBottom>
          {isDragActive ? 'Drop the subnet files here...' : 'Upload Subnet Files'}
        </Typography>
        <Typography variant="body2" color="text.secondary" mb={2}>
          Drag and drop your subnet files here, or click to select files
        </Typography>
        <Typography variant="caption" color="text.secondary" display="block" mb={2}>
          Supported formats: .txt, .csv (one subnet per line, e.g., 192.168.1.0/24)
        </Typography>

        <Box sx={{ mt: 2, p: 2, bgcolor: 'action.hover', borderRadius: 1, border: 1, borderColor: 'divider' }}>
          <Tooltip
            title={
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 1 }}>
                  Subnet File Configuration
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  Configure scope details before uploading your subnet file:
                </Typography>
                <Typography variant="body2" component="div" sx={{ mb: 1 }}>
                  • <strong>Scope Name:</strong> Unique identifier for this network scope
                </Typography>
                <Typography variant="body2" component="div" sx={{ mb: 1 }}>
                  • <strong>Description:</strong> Optional details about this scope's purpose
                </Typography>
                <Typography variant="body2" sx={{ mt: 1, fontStyle: 'italic' }}>
                  Note: Scope name is required before uploading any files.
                </Typography>
              </Box>
            }
            arrow
            placement="top"
          >
            <FormControlLabel
              control={
                <Checkbox
                  checked={showUploadOptions}
                  onChange={(e) => setShowUploadOptions(e.target.checked)}
                  onClick={(e) => e.stopPropagation()}
                />
              }
              label={
                <Box display="flex" alignItems="center" gap={1}>
                  <span>Configure scope details</span>
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

          <Collapse in={showUploadOptions}>
            <Box sx={{ mt: 2, ml: 4 }}>
              <Box sx={{ mb: 2 }}>
                <TextField
                  label="Scope Name"
                  placeholder="e.g., Internal Network, DMZ, External Ranges"
                  value={scopeName}
                  onChange={(e) => setScopeName(e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                  size="small"
                  fullWidth
                  required
                  helperText="Required: Enter a unique name for this network scope"
                  error={!scopeName.trim() && showUploadOptions}
                />
              </Box>
              <Box>
                <TextField
                  label="Description"
                  placeholder="Optional description of this scope's purpose or coverage"
                  value={scopeDescription}
                  onChange={(e) => setScopeDescription(e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                  size="small"
                  fullWidth
                  multiline
                  rows={2}
                  helperText="Optional: Describe the purpose or coverage of this scope"
                />
              </Box>
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
        <Alert severity="success" sx={{ mb: 2 }}>
          {uploadSuccess}
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