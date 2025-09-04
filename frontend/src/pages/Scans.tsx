import React, { useEffect, useState } from 'react';
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
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  CloudUpload as UploadIcon,
} from '@mui/icons-material';
import { getScans, deleteScan, uploadFile } from '../services/api';
import type { Scan } from '../services/api';

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

  const fetchScans = async () => {
    try {
      const data = await getScans();
      setScans(data);
    } catch (error) {
      console.error('Error fetching scans:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  // Upload functionality
  const onDrop = async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    setUploading(true);
    setUploadError(null);
    setUploadSuccess(null);

    try {
      const result = await uploadFile(file, enrichDns);
      setUploadSuccess(`File "${result.filename}" uploaded successfully!`);
      
      // Refresh the scans list to show the new upload
      await fetchScans();
      
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
      'text/xml': ['.xml'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/plain': ['.txt']
    },
    multiple: false,
  });

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
          Supported formats: Nmap XML, Eyewitness JSON/CSV, Masscan XML/JSON/List
        </Typography>
        
        <FormControlLabel
          control={
            <Checkbox
              checked={enrichDns}
              onChange={(e) => setEnrichDns(e.target.checked)}
              onClick={(e) => e.stopPropagation()}
            />
          }
          label="Enrich with DNS data"
          sx={{ mt: 1 }}
          onClick={(e) => e.stopPropagation()}
        />
        
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

      <Divider sx={{ mb: 3 }} />

      {/* Scans List */}
      <Typography variant="h5" gutterBottom>
        Your Scans
      </Typography>

      {scans.length === 0 ? (
        <Box textAlign="center" py={4}>
          <Typography variant="body1" color="text.secondary">
            No scans uploaded yet. Use the upload area above to get started.
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {scans.map((scan) => (
            <Grid item xs={12} sm={6} md={4} key={scan.id}>
              <Card>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                    <Typography variant="h6" component="div" noWrap>
                      {scan.filename}
                    </Typography>
                    <Box>
                      <IconButton
                        size="small"
                        onClick={() => handleViewScan(scan.id)}
                        color="primary"
                      >
                        <ViewIcon />
                      </IconButton>
                      <IconButton
                        size="small"
                        onClick={() => handleDeleteClick(scan)}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  </Box>

                  <Typography color="text.secondary" gutterBottom>
                    {new Date(scan.created_at).toLocaleString()}
                  </Typography>

                  {scan.scan_type && (
                    <Chip
                      label={scan.scan_type}
                      size="small"
                      sx={{ mb: 1 }}
                    />
                  )}

                  <Box mt={2}>
                    <Typography variant="body2" color="text.secondary">
                      Hosts: <strong>{scan.up_hosts}/{scan.total_hosts}</strong>
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Open Ports: <strong>{scan.open_ports}</strong>
                    </Typography>
                  </Box>

                  <Box mt={2}>
                    <Chip
                      label={`${scan.up_hosts}/${scan.total_hosts} hosts up`}
                      color={getStatusColor(scan.up_hosts, scan.total_hosts)}
                      size="small"
                    />
                  </Box>

                  <Box mt={2}>
                    <Button
                      fullWidth
                      variant="outlined"
                      onClick={() => handleViewScan(scan.id)}
                    >
                      View Details
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
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