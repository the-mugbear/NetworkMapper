import React, { useState, useEffect } from 'react';
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
  LinearProgress
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

const Scopes: React.FC = () => {
  const navigate = useNavigate();
  const [scopes, setScopes] = useState<ScopeSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [correlating, setCorrelating] = useState(false);

  // Upload form state
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scopeName, setScopeName] = useState('');
  const [scopeDescription, setScopeDescription] = useState('');

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

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    setSelectedFile(file || null);
  };

  const handleUploadSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    
    if (!selectedFile || !scopeName.trim()) {
      setError('Please select a file and enter a scope name');
      return;
    }

    try {
      setUploading(true);
      setError(null);
      
      await uploadSubnetFile(selectedFile, scopeName.trim(), scopeDescription.trim() || undefined);
      
      // Reset form
      setSelectedFile(null);
      setScopeName('');
      setScopeDescription('');
      setShowUploadForm(false);
      
      // Reload scopes
      await loadScopes();
      
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to upload subnet file');
      console.error('Error uploading subnet file:', err);
    } finally {
      setUploading(false);
    }
  };

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

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box p={3}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Scopes & Subnets
        </Typography>
        <Box display="flex" gap={2}>
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
            onClick={() => exportOutOfScopeReport('html')}
          >
            Export Out-of-Scope
          </Button>
          <Button
            variant="contained"
            startIcon={<UploadIcon />}
            onClick={() => setShowUploadForm(true)}
          >
            Upload Subnet File
          </Button>
        </Box>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Upload Dialog */}
      <Dialog open={showUploadForm} onClose={() => setShowUploadForm(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          Upload Subnet File
          <IconButton
            onClick={() => setShowUploadForm(false)}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <form onSubmit={handleUploadSubmit}>
          <DialogContent dividers>
            <Box display="flex" flexDirection="column" gap={3}>
              <TextField
                label="Scope Name"
                value={scopeName}
                onChange={(e) => setScopeName(e.target.value)}
                required
                fullWidth
                variant="outlined"
              />
              
              <TextField
                label="Description"
                value={scopeDescription}
                onChange={(e) => setScopeDescription(e.target.value)}
                multiline
                rows={3}
                fullWidth
                variant="outlined"
              />
              
              <Box>
                <input
                  accept=".txt,.csv"
                  style={{ display: 'none' }}
                  id="subnet-file-upload"
                  type="file"
                  onChange={handleFileSelect}
                  required
                />
                <label htmlFor="subnet-file-upload">
                  <Button
                    variant="outlined"
                    component="span"
                    startIcon={<CloudUpload />}
                    fullWidth
                    sx={{ mb: 1 }}
                  >
                    Select Subnet File (.txt, .csv)
                  </Button>
                </label>
                {selectedFile && (
                  <Typography variant="caption" display="block" color="textSecondary">
                    Selected: {selectedFile.name}
                  </Typography>
                )}
                <Typography variant="caption" display="block" color="textSecondary" sx={{ mt: 1 }}>
                  File should contain one subnet per line (e.g., 192.168.1.0/24)
                </Typography>
              </Box>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setShowUploadForm(false)}>
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="contained"
              disabled={uploading}
              startIcon={uploading ? <CircularProgress size={20} color="inherit" /> : undefined}
            >
              {uploading ? 'Uploading...' : 'Upload'}
            </Button>
          </DialogActions>
        </form>
      </Dialog>

      {/* Scopes Grid */}
      {scopes.length === 0 ? (
        <Card>
          <CardContent>
            <Box textAlign="center" py={4}>
              <Typography variant="h6" color="textSecondary" gutterBottom>
                No scopes found
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Upload a subnet file to get started.
              </Typography>
            </Box>
          </CardContent>
        </Card>
      ) : (
        <Grid container spacing={3}>
          {scopes.map((scope) => (
            <Grid item xs={12} md={6} lg={4} key={scope.id}>
              <Card>
                <CardContent>
                  <Typography variant="h6" component="h3" gutterBottom>
                    {scope.name}
                  </Typography>
                  {scope.description && (
                    <Typography variant="body2" color="textSecondary" paragraph>
                      {scope.description}
                    </Typography>
                  )}
                  <Box display="flex" gap={1} mb={2}>
                    <Chip
                      label={`${scope.subnet_count} subnets`}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  </Box>
                  <Typography variant="caption" color="textSecondary">
                    Created: {new Date(scope.created_at).toLocaleDateString()}
                  </Typography>
                </CardContent>
                <Divider />
                <CardActions>
                  <Button
                    size="small"
                    startIcon={<ViewIcon />}
                    onClick={() => navigate(`/scopes/${scope.id}`)}
                  >
                    View Details
                  </Button>
                  <Button
                    size="small"
                    startIcon={<ExportIcon />}
                    onClick={() => exportScopeReport(scope.id, 'html')}
                    color="success"
                  >
                    Export
                  </Button>
                  <Button
                    size="small"
                    startIcon={<DeleteIcon />}
                    onClick={() => handleDelete(scope.id, scope.name)}
                    color="error"
                  >
                    Delete
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
};

export default Scopes;