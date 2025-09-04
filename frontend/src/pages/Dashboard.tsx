import React, { useEffect, useState } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';
import { getDashboardStats, getPortStats, getOsStats } from '../services/api';
import type { DashboardStats, Scan, SubnetStats } from '../services/api';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface PortStat {
  port: number;
  service: string;
  count: number;
}

interface OsStat {
  os: string;
  count: number;
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [portStats, setPortStats] = useState<PortStat[]>([]);
  const [osStats, setOsStats] = useState<OsStat[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [dashboardData, portData, osData] = await Promise.all([
          getDashboardStats(),
          getPortStats(),
          getOsStats(),
        ]);
        
        setStats(dashboardData);
        setPortStats(portData);
        setOsStats(osData);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const portChartData = {
    labels: portStats.map(stat => `${stat.port}/${stat.service}`),
    datasets: [
      {
        label: 'Open Ports',
        data: portStats.map(stat => stat.count),
        backgroundColor: 'rgba(25, 118, 210, 0.6)',
        borderColor: 'rgba(25, 118, 210, 1)',
        borderWidth: 1,
      },
    ],
  };

  const osChartData = {
    labels: osStats.map(stat => stat.os),
    datasets: [
      {
        data: osStats.map(stat => stat.count),
        backgroundColor: [
          '#FF6384',
          '#36A2EB',
          '#FFCE56',
          '#4BC0C0',
          '#9966FF',
          '#FF9F40',
          '#C9CBCF',
          '#4BC0C0',
          '#FF6384',
          '#36A2EB',
        ],
      },
    ],
  };

  const getStateColor = (upHosts: number, totalHosts: number) => {
    if (totalHosts === 0) return 'default';
    const ratio = upHosts / totalHosts;
    if (ratio > 0.8) return 'success';
    if (ratio > 0.5) return 'warning';
    return 'error';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading dashboard...</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>

      <Grid container spacing={3}>
        {/* Stats Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Scans
              </Typography>
              <Typography variant="h4">
                {stats?.total_scans || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Hosts
              </Typography>
              <Typography variant="h4">
                {stats?.total_hosts || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Ports
              </Typography>
              <Typography variant="h4">
                {stats?.total_ports || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Subnets
              </Typography>
              <Typography variant="h4">
                {stats?.total_subnets || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Port Statistics Chart */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Most Common Open Ports
            </Typography>
            {portStats.length > 0 ? (
              <Box height="300px">
                <Bar
                  data={portChartData}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        position: 'top',
                      },
                    },
                    scales: {
                      y: {
                        beginAtZero: true,
                      },
                    },
                  }}
                />
              </Box>
            ) : (
              <Typography>No port data available</Typography>
            )}
          </Paper>
        </Grid>

        {/* OS Distribution Chart */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Operating System Distribution
            </Typography>
            {osStats.length > 0 ? (
              <Box height="300px" display="flex" justifyContent="center">
                <Doughnut
                  data={osChartData}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        position: 'bottom',
                      },
                    },
                  }}
                />
              </Box>
            ) : (
              <Typography>No OS data available</Typography>
            )}
          </Paper>
        </Grid>

        {/* Subnet Statistics Table */}
        <Grid item xs={12}>
          <Paper>
            <Box p={2}>
              <Typography variant="h6" gutterBottom>
                Subnet Statistics
              </Typography>
              {stats?.subnet_stats && stats.subnet_stats.length > 0 ? (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Subnet (CIDR)</TableCell>
                        <TableCell>Scope</TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell align="right">Discovered Hosts</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {stats.subnet_stats.map((subnet: SubnetStats) => (
                        <TableRow key={subnet.id}>
                          <TableCell>
                            <Typography variant="body2" fontFamily="monospace">
                              {subnet.cidr}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={subnet.scope_name} 
                              color="primary" 
                              variant="outlined" 
                              size="small" 
                            />
                          </TableCell>
                          <TableCell>{subnet.description || 'No description'}</TableCell>
                          <TableCell align="right">
                            <Chip
                              label={subnet.host_count}
                              color={subnet.host_count > 0 ? 'success' : 'default'}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography>No subnet data available. Upload subnet files to get started!</Typography>
              )}
            </Box>
          </Paper>
        </Grid>

        {/* Recent Scans Table */}
        <Grid item xs={12}>
          <Paper>
            <Box p={2}>
              <Typography variant="h6" gutterBottom>
                Recent Scans
              </Typography>
              {stats?.recent_scans && stats.recent_scans.length > 0 ? (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Filename</TableCell>
                        <TableCell>Scan Type</TableCell>
                        <TableCell>Date</TableCell>
                        <TableCell>Hosts</TableCell>
                        <TableCell>Open Ports</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {stats.recent_scans.map((scan: Scan) => (
                        <TableRow key={scan.id}>
                          <TableCell>{scan.filename}</TableCell>
                          <TableCell>{scan.scan_type || 'N/A'}</TableCell>
                          <TableCell>
                            {new Date(scan.created_at).toLocaleDateString()}
                          </TableCell>
                          <TableCell>
                            {scan.up_hosts}/{scan.total_hosts}
                          </TableCell>
                          <TableCell>{scan.open_ports}</TableCell>
                          <TableCell>
                            <Chip
                              label={`${scan.up_hosts}/${scan.total_hosts} hosts up`}
                              color={getStateColor(scan.up_hosts, scan.total_hosts)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography>No scans available. Upload an Nmap XML file to get started!</Typography>
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}