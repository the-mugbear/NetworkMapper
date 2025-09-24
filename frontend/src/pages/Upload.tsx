import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone, FileRejection } from 'react-dropzone';
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
import { getIngestionJob, uploadFile } from '../services/api';
import type { IngestionJob } from '../services/api';

export default function Upload() {
  const navigate = useNavigate();
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [enrichDns, setEnrichDns] = useState(false);
  const [jobId, setJobId] = useState<number | null>(null);
  const [jobStatus, setJobStatus] = useState<IngestionJob | null>(null);
  const jobCompletionHandled = useRef(false);

  const onDrop = async (acceptedFiles: File[], rejectedFiles: FileRejection[]) => {
    const file = acceptedFiles[0];
    if (!file) {
      return;
    }
    setUploading(true);
    setError(null);
    setSuccess(null);

    try {
      const dnsConfig = { enabled: enrichDns };
      const result = await uploadFile(file, dnsConfig);
      setJobId(result.job_id);
      jobCompletionHandled.current = false;
      setJobStatus(null);
      setSuccess(
        `File "${result.filename}" queued for processing. Job #${result.job_id}.`
      );
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  useEffect(() => {
    if (!jobId) {
      return undefined;
    }

    let isActive = true;

    const pollJob = async () => {
      try {
        const job = await getIngestionJob(jobId);
        if (!isActive) return;
        setJobStatus(job);

        if (job.status === 'completed') {
          setSuccess(
            `Processing complete for "${job.filename}". Redirecting to scan details...`
          );
          if (job.scan_id && !jobCompletionHandled.current) {
            jobCompletionHandled.current = true;
            setTimeout(() => {
              navigate(`/scans/${job.scan_id}`);
            }, 2000);
          }
          return false;
        }

        if (job.status == 'failed') {
          setError(job.error_message || 'Ingestion job failed. Check server logs for details.');
          setSuccess(null);
          return false;
        }

        return true;
      } catch (error) {
        if (isActive) {
          console.error('Failed to fetch ingestion job status', error);
        }
        return true;
      }
    };

    let intervalId: ReturnType<typeof setInterval> | null = null;

    const startPolling = async () => {
      const shouldContinue = await pollJob();
      if (!isActive || !shouldContinue) {
        return;
      }
      intervalId = setInterval(async () => {
        const keepGoing = await pollJob();
        if (!keepGoing && intervalId) {
          clearInterval(intervalId);
          intervalId = null;
        }
      }, 4000);
    };

    startPolling();

    return () => {
      isActive = false;
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [jobId, navigate]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    onDragEnter: () => {},
    onDragOver: () => {},
    onDragLeave: () => {},
    accept: {
      'text/xml': ['.xml'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/plain': ['.txt', '.gnmap'],
      'application/xml': ['.nessus']
    },
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
              Supported formats: .xml (Nmap/Masscan), .nessus (Nessus), .gnmap (Nmap), .json (Masscan/Eyewitness), .csv (Eyewitness), .txt (Masscan)
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

      {jobStatus && jobStatus.status !== 'failed' && (
        <Alert
          severity={jobStatus.status === 'completed' ? 'success' : 'info'}
          sx={{ mt: 2 }}
        >
          <strong>Job Status:</strong> {jobStatus.status.toUpperCase()}
          {jobStatus.message && (
            <>
              <br />
              {jobStatus.message}
            </>
          )}
          {jobStatus.status !== 'completed' && (
            <>
              <br />
              Waiting for background processing to finish...
              <LinearProgress sx={{ mt: 1 }} />
            </>
          )}
        </Alert>
      )}

      {jobStatus && jobStatus.status === 'failed' && (
        <Alert severity="error" sx={{ mt: 2 }}>
          <strong>Ingestion Failed:</strong> {jobStatus.error_message || 'Unable to process this file.'}
          {jobStatus.message && (
            <>
              <br />
              {jobStatus.message}
            </>
          )}
          {jobStatus.parse_error_id && (
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
              Parse error ID: {jobStatus.parse_error_id}
            </Typography>
          )}
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Review the upload format and try again. Inspect the Parse Errors view for additional diagnostics.
          </Typography>
          {jobStatus.parse_error_id && (
            <Button
              size="small"
              sx={{ mt: 1 }}
              onClick={() => navigate('/parse-errors')}
            >
              View Parse Errors
            </Button>
          )}
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
            <li><strong>Nessus:</strong> Export scan results as .nessus file from Nessus interface</li>
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
