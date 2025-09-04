import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Alert,
  Tabs,
  Tab,
  MenuItem,
  FormControl,
  Select,
  InputLabel,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
} from '@mui/material';
import {
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Close as CloseIcon,
  ExpandMore as ExpandMoreIcon,
  Assignment as AssignmentIcon,
} from '@mui/icons-material';
import {
  getParseErrors,
  getParseError,
  updateParseErrorStatus,
  deleteParseError,
  getParseErrorStats,
  type ParseErrorSummary,
  type ParseError,
} from '../services/api';

const ParseErrors: React.FC = () => {
  const [errors, setErrors] = useState<ParseErrorSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedError, setSelectedError] = useState<ParseError | null>(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    loadParseErrors();
    loadStats();
  }, [statusFilter]);

  const loadParseErrors = async () => {
    try {
      setLoading(true);
      const filterParams = statusFilter !== 'all' ? { status: statusFilter } : {};
      const data = await getParseErrors(filterParams);
      setErrors(data);
    } catch (error) {
      console.error('Error loading parse errors:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const statsData = await getParseErrorStats();
      setStats(statsData);
    } catch (error) {
      console.error('Error loading parse error stats:', error);
    }
  };

  const handleViewDetails = async (errorId: number) => {
    try {
      const errorDetails = await getParseError(errorId);
      setSelectedError(errorDetails);
      setDetailDialogOpen(true);
    } catch (error) {
      console.error('Error loading error details:', error);
    }
  };

  const handleUpdateStatus = async (errorId: number, newStatus: string) => {
    try {
      await updateParseErrorStatus(errorId, newStatus);
      await loadParseErrors();
      await loadStats();
      if (selectedError?.id === errorId) {
        setDetailDialogOpen(false);
        setSelectedError(null);
      }
    } catch (error) {
      console.error('Error updating status:', error);
    }
  };

  const handleDelete = async (errorId: number) => {
    if (window.confirm('Are you sure you want to delete this parse error record?')) {
      try {
        await deleteParseError(errorId);
        await loadParseErrors();
        await loadStats();
        if (selectedError?.id === errorId) {
          setDetailDialogOpen(false);
          setSelectedError(null);
        }
      } catch (error) {
        console.error('Error deleting parse error:', error);
      }
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'unresolved': return 'error';
      case 'reviewed': return 'warning';
      case 'fixed': return 'success';
      case 'ignored': return 'default';
      default: return 'default';
    }
  };

  const getErrorTypeIcon = (errorType: string) => {
    switch (errorType) {
      case 'parsing_error': return <ErrorIcon color="error" />;
      case 'validation_error': return <WarningIcon color="warning" />;
      case 'format_error': return <InfoIcon color="info" />;
      default: return <ErrorIcon />;
    }
  };

  const formatFileSize = (bytes: number | null) => {
    if (!bytes) return 'N/A';
    const kb = bytes / 1024;
    const mb = kb / 1024;
    if (mb >= 1) return `${mb.toFixed(1)} MB`;
    if (kb >= 1) return `${kb.toFixed(1)} KB`;
    return `${bytes} bytes`;
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">
          Parse Errors
        </Typography>
        <Button
          startIcon={<RefreshIcon />}
          onClick={() => { loadParseErrors(); loadStats(); }}
        >
          Refresh
        </Button>
      </Box>

      {/* Statistics Cards */}
      {stats && (
        <Grid container spacing={2} mb={3}>
          <Grid item xs={6} sm={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Total Errors</Typography>
                <Typography variant="h4">{stats.total_errors}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Unresolved</Typography>
                <Typography variant="h4" color="error.main">{stats.unresolved}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Reviewed</Typography>
                <Typography variant="h4" color="warning.main">{stats.reviewed}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Fixed</Typography>
                <Typography variant="h4" color="success.main">{stats.fixed}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Filter Controls */}
      <Box mb={3}>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Filter by Status</InputLabel>
          <Select
            value={statusFilter}
            label="Filter by Status"
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">All Errors</MenuItem>
            <MenuItem value="unresolved">Unresolved</MenuItem>
            <MenuItem value="reviewed">Reviewed</MenuItem>
            <MenuItem value="fixed">Fixed</MenuItem>
            <MenuItem value="ignored">Ignored</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Errors Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Type</TableCell>
                <TableCell>Filename</TableCell>
                <TableCell>File Type</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Date</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    Loading parse errors...
                  </TableCell>
                </TableRow>
              ) : errors.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="textSecondary">
                      {statusFilter === 'all' ? 'No parse errors found' : `No ${statusFilter} errors found`}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                errors.map((error) => (
                  <TableRow key={error.id}>
                    <TableCell>
                      <Tooltip title={error.error_type}>
                        {getErrorTypeIcon(error.error_type)}
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {error.filename}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={error.file_type || 'Unknown'} 
                        size="small" 
                        variant="outlined" 
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ maxWidth: 300 }} noWrap>
                        {error.user_message || 'No message available'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={error.status} 
                        color={getStatusColor(error.status) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption">
                        {new Date(error.created_at).toLocaleDateString()}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <IconButton
                        size="small"
                        onClick={() => handleViewDetails(error.id)}
                      >
                        <ViewIcon />
                      </IconButton>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDelete(error.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Detail Dialog */}
      <Dialog 
        open={detailDialogOpen} 
        onClose={() => setDetailDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          <Box display="flex" justifyContent="space-between" alignItems="center">
            Parse Error Details
            <IconButton onClick={() => setDetailDialogOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedError && (
            <Box>
              <Grid container spacing={3} mb={3}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="h6" gutterBottom>File Information</Typography>
                  <Typography><strong>Filename:</strong> {selectedError.filename}</Typography>
                  <Typography><strong>File Type:</strong> {selectedError.file_type || 'Unknown'}</Typography>
                  <Typography><strong>File Size:</strong> {formatFileSize(selectedError.file_size)}</Typography>
                  <Typography><strong>Error Type:</strong> {selectedError.error_type}</Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="h6" gutterBottom>Status</Typography>
                  <Box display="flex" gap={1} flexWrap="wrap">
                    {['unresolved', 'reviewed', 'fixed', 'ignored'].map((status) => (
                      <Button
                        key={status}
                        variant={selectedError.status === status ? 'contained' : 'outlined'}
                        size="small"
                        onClick={() => handleUpdateStatus(selectedError.id, status)}
                      >
                        {status}
                      </Button>
                    ))}
                  </Box>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom>User Message</Typography>
              <Alert severity="info" sx={{ mb: 2 }}>
                {selectedError.user_message || 'No user-friendly message available'}
              </Alert>

              <Typography variant="h6" gutterBottom>Technical Details</Typography>
              <Alert severity="error" sx={{ mb: 2 }}>
                <Typography variant="body2" fontFamily="monospace">
                  {selectedError.error_message}
                </Typography>
              </Alert>

              {selectedError.file_preview && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6">File Preview</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box 
                      component="pre" 
                      sx={{ 
                        backgroundColor: 'grey.100',
                        p: 2,
                        borderRadius: 1,
                        overflow: 'auto',
                        maxHeight: 300,
                        fontSize: '0.875rem',
                        fontFamily: 'monospace'
                      }}
                    >
                      {selectedError.file_preview}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}

              {selectedError.error_details && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6">Technical Error Details</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box 
                      component="pre" 
                      sx={{ 
                        backgroundColor: 'grey.100',
                        p: 2,
                        borderRadius: 1,
                        overflow: 'auto',
                        maxHeight: 400,
                        fontSize: '0.75rem',
                        fontFamily: 'monospace'
                      }}
                    >
                      {JSON.stringify(selectedError.error_details, null, 2)}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailDialogOpen(false)}>Close</Button>
          {selectedError && (
            <Button
              color="error"
              onClick={() => handleDelete(selectedError.id)}
            >
              Delete Error
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ParseErrors;