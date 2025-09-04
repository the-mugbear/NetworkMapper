import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
  InputAdornment,
} from '@mui/material';
import {
  Search as SearchIcon,
  Computer as ComputerIcon,
} from '@mui/icons-material';
import { getHosts } from '../services/api';
import type { Host } from '../services/api';

export default function Hosts() {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [stateFilter, setStateFilter] = useState('');

  const fetchHosts = async () => {
    try {
      const params: any = {};
      if (searchTerm) params.search = searchTerm;
      if (stateFilter) params.state = stateFilter;
      
      const data = await getHosts(params);
      setHosts(data);
    } catch (error) {
      console.error('Error fetching hosts:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHosts();
  }, [searchTerm, stateFilter]);

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
  };

  const handleStateFilterChange = (event: any) => {
    setStateFilter(event.target.value);
  };

  const getStateColor = (state: string | null) => {
    switch (state) {
      case 'up': return 'success';
      case 'down': return 'error';
      default: return 'default';
    }
  };

  const handleViewHost = (hostId: number) => {
    navigate(`/hosts/${hostId}`);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading hosts...</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Discovered Hosts
      </Typography>

      {/* Filters */}
      <Box mb={3}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Search hosts"
              value={searchTerm}
              onChange={handleSearchChange}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              placeholder="Search by IP, hostname, or OS..."
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth>
              <InputLabel>State</InputLabel>
              <Select
                value={stateFilter}
                label="State"
                onChange={handleStateFilterChange}
              >
                <MenuItem value="">All States</MenuItem>
                <MenuItem value="up">Up</MenuItem>
                <MenuItem value="down">Down</MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Box>

      {hosts.length === 0 ? (
        <Box textAlign="center" py={8}>
          <ComputerIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No hosts found
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Try adjusting your search filters or upload more scan results
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {hosts.map((host) => (
            <Grid item xs={12} sm={6} md={4} key={host.id}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <ComputerIcon sx={{ mr: 1, color: 'primary.main' }} />
                    <Typography variant="h6" component="div">
                      {host.ip_address}
                    </Typography>
                  </Box>

                  {host.hostname && (
                    <Typography color="text.secondary" gutterBottom>
                      {host.hostname}
                    </Typography>
                  )}

                  <Box mb={2}>
                    <Chip
                      label={host.state || 'unknown'}
                      color={getStateColor(host.state)}
                      size="small"
                    />
                  </Box>

                  {host.os_name && (
                    <Typography variant="body2" color="text.secondary" mb={1}>
                      <strong>OS:</strong> {host.os_name}
                    </Typography>
                  )}

                  <Typography variant="body2" color="text.secondary" mb={2}>
                    <strong>Open Ports:</strong> {host.ports?.filter(port => port.state === 'open').length || 0}
                  </Typography>

                  <Typography variant="body2" color="text.secondary" mb={2}>
                    <strong>Total Ports:</strong> {host.ports?.length || 0}
                  </Typography>

                  <Button
                    fullWidth
                    variant="outlined"
                    onClick={() => handleViewHost(host.id)}
                  >
                    View Details
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
}