import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Typography,
  TextField,
  Card,
  CardContent,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Autocomplete,
  CircularProgress,
  Alert,
  TablePagination,
  IconButton,
  Tooltip,
  InputAdornment,
  Divider
} from '@mui/material';
import {
  Search as SearchIcon,
  ContentCopy as CopyIcon,
  Security as SecurityIcon,
  FilterList as FilterIcon
} from '@mui/icons-material';

interface CredentialEntry {
  vendor: string;
  username: string;
  password: string;
}

export default function DefaultCredentials() {
  const [credentials, setCredentials] = useState<CredentialEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedVendor, setSelectedVendor] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  // Load and parse CSV data
  useEffect(() => {
    const loadCredentials = async () => {
      try {
        setLoading(true);
        const response = await fetch('/DefaultCreds-Cheat-Sheet.csv');
        if (!response.ok) {
          throw new Error('Failed to load credentials data');
        }

        const csvText = await response.text();
        const lines = csvText.split('\n');
        const headers = lines[0].split(',');

        const parsedCredentials: CredentialEntry[] = [];

        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (line) {
            const values = line.split(',');
            if (values.length >= 3) {
              parsedCredentials.push({
                vendor: values[0].trim(),
                username: values[1].trim() || '<blank>',
                password: values[2].trim() || '<blank>'
              });
            }
          }
        }

        setCredentials(parsedCredentials);
        setError(null);
      } catch (err) {
        console.error('Error loading credentials:', err);
        setError('Failed to load default credentials data');
      } finally {
        setLoading(false);
      }
    };

    loadCredentials();
  }, []);

  // Get unique vendors for the autocomplete
  const vendors = useMemo(() => {
    const uniqueVendors = Array.from(new Set(credentials.map(cred => cred.vendor)))
      .filter(vendor => vendor && vendor !== 'productvendor')
      .sort();
    return uniqueVendors;
  }, [credentials]);

  // Filter credentials based on selected vendor and search term
  const filteredCredentials = useMemo(() => {
    let filtered = credentials;

    // Filter by vendor
    if (selectedVendor) {
      filtered = filtered.filter(cred =>
        cred.vendor.toLowerCase() === selectedVendor.toLowerCase()
      );
    }

    // Filter by search term (searches vendor, username, password)
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      filtered = filtered.filter(cred =>
        cred.vendor.toLowerCase().includes(searchLower) ||
        cred.username.toLowerCase().includes(searchLower) ||
        cred.password.toLowerCase().includes(searchLower)
      );
    }

    return filtered;
  }, [credentials, selectedVendor, searchTerm]);

  // Paginated credentials
  const paginatedCredentials = useMemo(() => {
    const startIndex = page * rowsPerPage;
    return filteredCredentials.slice(startIndex, startIndex + rowsPerPage);
  }, [filteredCredentials, page, rowsPerPage]);

  // Copy to clipboard function
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Format credential display
  const formatCredential = (value: string) => {
    if (value === '<blank>' || value === '') {
      return '(blank)';
    }
    return value;
  };

  // Handle page change
  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  // Handle rows per page change
  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // Reset filters
  const resetFilters = () => {
    setSelectedVendor(null);
    setSearchTerm('');
    setPage(0);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading default credentials...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Default Credentials Database
      </Typography>

      <Typography variant="body1" color="text.secondary" paragraph>
        Search through a comprehensive database of default credentials for various products and vendors.
        Use this information for security testing and vulnerability assessment.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Filter Section */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box display="flex" alignItems="center" gap={2} mb={2}>
          <FilterIcon color="primary" />
          <Typography variant="h6">
            Filters
          </Typography>
          <Chip
            label={`${filteredCredentials.length} of ${credentials.length} credentials`}
            color="primary"
            variant="outlined"
          />
        </Box>

        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <Autocomplete
              options={vendors}
              value={selectedVendor}
              onChange={(event, newValue) => {
                setSelectedVendor(newValue);
                setPage(0);
              }}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Select Vendor"
                  variant="outlined"
                  placeholder="Choose a vendor..."
                />
              )}
              clearOnEscape
            />
          </Grid>

          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Search Credentials"
              variant="outlined"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(0);
              }}
              placeholder="Search vendor, username, or password..."
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
          </Grid>

          <Grid item xs={12} md={2}>
            <Box textAlign="right">
              <Chip
                label="Clear Filters"
                variant="outlined"
                onClick={resetFilters}
                clickable
                sx={{ cursor: 'pointer' }}
              />
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Statistics Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <SecurityIcon color="primary" fontSize="large" />
                <Box>
                  <Typography variant="h6">
                    {credentials.length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Credentials
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <FilterIcon color="success" fontSize="large" />
                <Box>
                  <Typography variant="h6">
                    {vendors.length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Unique Vendors
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <SearchIcon color="warning" fontSize="large" />
                <Box>
                  <Typography variant="h6">
                    {filteredCredentials.length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Filtered Results
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <CopyIcon color="info" fontSize="large" />
                <Box>
                  <Typography variant="h6">
                    {selectedVendor || 'All'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Selected Vendor
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Results Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell><strong>Vendor/Product</strong></TableCell>
                <TableCell><strong>Username</strong></TableCell>
                <TableCell><strong>Password</strong></TableCell>
                <TableCell align="center"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedCredentials.map((cred, index) => (
                <TableRow key={index} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                      {cred.vendor}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          backgroundColor: 'action.hover',
                          px: 1,
                          py: 0.5,
                          borderRadius: 1,
                          color: cred.username === '<blank>' ? 'text.secondary' : 'text.primary',
                          fontStyle: cred.username === '<blank>' ? 'italic' : 'normal'
                        }}
                      >
                        {formatCredential(cred.username)}
                      </Typography>
                      <Tooltip title="Copy username">
                        <IconButton
                          size="small"
                          onClick={() => copyToClipboard(cred.username === '<blank>' ? '' : cred.username)}
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          backgroundColor: 'action.hover',
                          px: 1,
                          py: 0.5,
                          borderRadius: 1,
                          color: cred.password === '<blank>' ? 'text.secondary' : 'text.primary',
                          fontStyle: cred.password === '<blank>' ? 'italic' : 'normal'
                        }}
                      >
                        {formatCredential(cred.password)}
                      </Typography>
                      <Tooltip title="Copy password">
                        <IconButton
                          size="small"
                          onClick={() => copyToClipboard(cred.password === '<blank>' ? '' : cred.password)}
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                  <TableCell align="center">
                    <Tooltip title="Copy username:password">
                      <IconButton
                        size="small"
                        onClick={() => {
                          const username = cred.username === '<blank>' ? '' : cred.username;
                          const password = cred.password === '<blank>' ? '' : cred.password;
                          copyToClipboard(`${username}:${password}`);
                        }}
                        color="primary"
                      >
                        <CopyIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Divider />

        <TablePagination
          rowsPerPageOptions={[10, 25, 50, 100]}
          component="div"
          count={filteredCredentials.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>

      {/* Footer Info */}
      <Box mt={3} p={2} bgcolor="action.hover" borderRadius={1}>
        <Typography variant="caption" color="text.secondary">
          <strong>Security Notice:</strong> This database is intended for authorized security testing and vulnerability
          assessment only. Always ensure you have proper authorization before testing credentials on any system.
          The data is sourced from publicly available default credential information.
        </Typography>
      </Box>
    </Box>
  );
}