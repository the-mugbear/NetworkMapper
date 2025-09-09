import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import {
  Box,
  Paper,
  Typography,
  Button,
  Alert,
  CircularProgress,
  LinearProgress,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import { CloudUpload as UploadIcon } from '@mui/icons-material';
import { uploadFile } from '../services/api';

export default function Upload() {
  const navigate = useNavigate();
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [enrichDns, setEnrichDns] = useState(false);

  const onDrop = async (acceptedFiles: File[], rejectedFiles: any[]) => {
    console.log('onDrop called:', { acceptedFiles, rejectedFiles });
    const file = acceptedFiles[0];
    if (!file) {
      console.log('No accepted file');
      return;
    }

    console.log('File details:', { name: file.name, type: file.type, size: file.size });
    setUploading(true);
    setError(null);
    setSuccess(null);

    try {
      const result = await uploadFile(file, enrichDns);
      setSuccess(`File "${result.filename}" uploaded successfully!`);
      
      setTimeout(() => {
        navigate(`/scans/${result.scan_id}`);
      }, 2000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    onDragEnter: () => console.log('Drag enter'),
    onDragOver: () => console.log('Drag over'), 
    onDragLeave: () => console.log('Drag leave'),
    maxFiles: 1,
    disabled: uploading,
  });

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Upload Scan Results
      </Typography>
      
      <Paper
        {...getRootProps()}
        sx={{
          p: 4,
          mt: 3,
          textAlign: 'center',
          border: '2px dashed',
          borderColor: isDragActive ? 'primary.main' : 'grey.300',
          backgroundColor: isDragActive ? 'action.hover' : 'background.paper',
          cursor: uploading ? 'not-allowed' : 'pointer',
          transition: 'all 0.3s ease',
          '&:hover': {
            borderColor: 'primary.main',
            backgroundColor: 'action.hover',
          },
        }}
      >
        <input {...getInputProps()} />
        
        {uploading ? (
          <Box>
            <CircularProgress size={60} />
            <Typography variant="h6" sx={{ mt: 2 }}>
              Uploading and parsing file...
            </Typography>
            <LinearProgress sx={{ mt: 2, maxWidth: 400, mx: 'auto' }} />
          </Box>
        ) : (
          <Box>
            <UploadIcon sx={{ fontSize: 60, color: 'primary.main', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              {isDragActive ? 'Drop the file here' : 'Drag & drop a scan file here, or click to select'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Supported formats: .xml (Nmap/Masscan), .gnmap (Nmap), .json (Masscan/Eyewitness), .csv (Eyewitness), .txt (Masscan)
            </Typography>
            <Button variant="outlined" sx={{ mt: 2 }}>
              Select File
            </Button>
            <FormControlLabel
              control={
                <Checkbox
                  checked={enrichDns}
                  onChange={(e) => setEnrichDns(e.target.checked)}
                  disabled={uploading}
                />
              }
              label="Enrich with DNS data (reverse lookup, zone transfers)"
              sx={{ mt: 2, display: 'block' }}
            />
          </Box>
        )}
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mt: 2 }}>
          {success}
        </Alert>
      )}

      <Box sx={{ mt: 4 }}>
        <Typography variant="h6" gutterBottom>
          Instructions:
        </Typography>
        <Typography variant="body2" component="div">
          <ol>
            <li><strong>Nmap XML:</strong> <code>nmap -oX scan.xml target</code></li>
            <li><strong>Nmap Grepable:</strong> <code>nmap -oG scan.gnmap target</code></li>
            <li><strong>Masscan:</strong> <code>masscan -p1-65535 --rate 1000 -oX scan.xml target</code></li>
            <li><strong>Eyewitness:</strong> Use the CSV or JSON export from EyeWitness reports</li>
            <li>Upload the generated file using the form above</li>
            <li>Results will be correlated with your defined scopes automatically</li>
            <li>Enable DNS enrichment for additional hostname and DNS record discovery</li>
          </ol>
        </Typography>
      </Box>
    </Box>
  );
}