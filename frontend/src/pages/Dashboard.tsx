import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  Divider,
  Stack,
} from '@mui/material';
import {
  Chart as ChartJS,
  Title,
  Tooltip as ChartTooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import {
  getDashboardStats,
  getOsStats,
  getRiskInsights,
  getRecentIngestionJobs,
} from '../services/api';
import type {
  DashboardStats,
  Scan,
  SubnetStats,
  RiskInsightResponse,
  HostRiskExposure,
  PortOfInterestSummary,
  VulnerabilityHotspot,
  IngestionJob,
} from '../services/api';
import RiskAssessmentWidget from '../components/RiskAssessmentWidget';
import RiskSummaryWidget from '../components/RiskSummaryWidget';
import CriticalFindingsWidget from '../components/CriticalFindingsWidget';
import NoteAltIcon from '@mui/icons-material/NoteAlt';
import BookmarkIcon from '@mui/icons-material/BookmarkAdded';
import VisibilityIcon from '@mui/icons-material/Visibility';

ChartJS.register(Title, ChartTooltip, Legend, ArcElement);

interface OsStat {
  os: string;
  count: number;
}

const NOTE_STATUS_META: Record<string, { label: string; color: 'info' | 'warning' | 'success' | 'default' }> = {
  open: { label: 'Open', color: 'info' },
  in_progress: { label: 'In Progress', color: 'warning' },
  resolved: { label: 'Resolved', color: 'success' },
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [osStats, setOsStats] = useState<OsStat[]>([]);
  const [riskInsights, setRiskInsights] = useState<RiskInsightResponse | null>(null);
  const [ingestionJobs, setIngestionJobs] = useState<IngestionJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [dashboardData, osData, riskData, jobData] = await Promise.all([
          getDashboardStats(),
          getOsStats(),
          getRiskInsights(),
          getRecentIngestionJobs(5),
        ]);

        setStats(dashboardData);
        setOsStats(osData);
        setRiskInsights(riskData);
        setIngestionJobs(jobData);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleSubnetClick = (subnet: SubnetStats) => {
    navigate(`/hosts?subnets=${encodeURIComponent(subnet.cidr)}`);
  };

  const osChartData = {
    labels: osStats.map((stat) => stat.os),
    datasets: [
      {
        data: osStats.map((stat) => stat.count),
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

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading dashboard...</Typography>
      </Box>
    );
  }

  const highRiskHosts: HostRiskExposure[] = riskInsights?.ports_of_interest.top_hosts ?? [];
  const portSummary: PortOfInterestSummary[] = riskInsights?.ports_of_interest.summary ?? [];
  const vulnerabilityHotspots: VulnerabilityHotspot[] = riskInsights?.vulnerability_hotspots ?? [];
  const noteActivity = stats?.note_activity;

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Security Intelligence Dashboard
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={6}>
          <RiskSummaryWidget />
        </Grid>

        <Grid item xs={12} lg={6}>
          <CriticalFindingsWidget />
        </Grid>

        <Grid item xs={12}>
          <Card sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Environment Overview
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="primary">
                      {stats?.total_scans || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Scans
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="primary">
                      {stats?.total_hosts || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Hosts
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="primary">
                      {stats?.total_ports || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Ports
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <Typography variant="h5" color="primary">
                      {stats?.total_subnets || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Subnets
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                High-Risk Hosts
              </Typography>
              {highRiskHosts.length ? (
                <List dense sx={{ maxHeight: 360, overflow: 'auto' }}>
                  {highRiskHosts.slice(0, 6).map((host) => (
                    <React.Fragment key={host.host_id}>
                      <ListItem alignItems="flex-start">
                        <ListItemText
                          primary={
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                              <Box>
                                <Typography variant="subtitle1" fontFamily="monospace">
                                  {host.ip_address}
                                </Typography>
                                {host.hostname && (
                                  <Typography variant="body2" color="text.secondary">
                                    {host.hostname}
                                  </Typography>
                                )}
                              </Box>
                              <Chip label={`Score ${host.risk_score}`} color="error" size="small" />
                            </Box>
                          }
                          secondary={
                            <Box mt={1}>
                              <Box display="flex" gap={0.5} flexWrap="wrap" mb={1}>
                                {host.ports_of_interest.map((port) => (
                                  <Chip
                                    key={`${host.host_id}-${port.port}`}
                                    label={`${port.port}/${port.service}`}
                                    size="small"
                                    variant="outlined"
                                    color="warning"
                                  />
                                ))}
                              </Box>
                              <Box display="flex" gap={1}>
                                <Chip label={`${host.critical} critical`} color="error" size="small" />
                                <Chip label={`${host.high} high`} color="warning" size="small" />
                                <Chip label={`${host.medium} medium`} color="info" size="small" />
                              </Box>
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider component="li" />
                    </React.Fragment>
                  ))}
                </List>
              ) : (
                <Typography color="text.secondary">No high-risk hosts detected.</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Ports of Interest Exposure
              </Typography>
              {portSummary.length ? (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Category</TableCell>
                        <TableCell align="right">Hosts</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {portSummary.slice(0, 8).map((port) => (
                        <TableRow key={port.port}>
                          <TableCell>
                            <Tooltip title={port.rationale} arrow>
                              <Box>
                                <Typography variant="body2" fontFamily="monospace">
                                  {port.port}/{port.protocol}
                                </Typography>
                                <Typography variant="body2">{port.label}</Typography>
                              </Box>
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            <Chip label={port.category} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body1">{port.open_host_count}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography color="text.secondary">No exposed ports of interest detected.</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {noteActivity && (
          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6" gutterBottom>
                    Recent Note Activity
                  </Typography>
                  <Chip
                    icon={<NoteAltIcon fontSize="small" />}
                    label={`${noteActivity.total_notes} total`}
                    size="small"
                    color="primary"
                    variant="outlined"
                  />
                </Box>
                <Stack direction="row" spacing={1} mb={2} flexWrap="wrap">
                  <Chip
                    icon={<BookmarkIcon fontSize="small" />}
                    label={`${noteActivity.following_count} following`}
                    size="small"
                    color="secondary"
                    variant="outlined"
                  />
                  <Chip
                    icon={<VisibilityIcon fontSize="small" />}
                    label={`${noteActivity.active_host_count} hosts touched`}
                    size="small"
                    color="info"
                    variant="outlined"
                  />
                </Stack>
                {noteActivity.recent_notes.length ? (
                  <List dense sx={{ maxHeight: 320, overflow: 'auto' }}>
                    {noteActivity.recent_notes.map((note) => {
                      const meta = NOTE_STATUS_META[note.status] ?? NOTE_STATUS_META.open;
                      const timestamp = note.updated_at || note.created_at;
                      return (
                        <React.Fragment key={`note-${note.note_id}`}>
                          <ListItem
                            alignItems="flex-start"
                            secondaryAction={
                              <Chip
                                label={meta.label}
                                color={meta.color}
                                size="small"
                              />
                            }
                          >
                            <ListItemText
                              primary={
                                <Typography variant="subtitle2" fontFamily="monospace">
                                  {note.ip_address}
                                  {note.hostname ? ` · ${note.hostname}` : ''}
                                </Typography>
                              }
                              secondary={
                                <Typography variant="body2" color="text.secondary">
                                  {note.preview}
                                  <Typography component="span" variant="caption" display="block">
                                    Logged {new Date(note.created_at).toLocaleString()}
                                    {note.updated_at && ` · Updated ${new Date(timestamp).toLocaleString()}`}
                                  </Typography>
                                </Typography>
                              }
                            />
                          </ListItem>
                          <Divider component="li" />
                        </React.Fragment>
                      );
                    })}
                  </List>
                ) : (
                  <Typography color="text.secondary">
                    You have not added any notes yet. Capture observations when reviewing hosts to see them here.
                  </Typography>
                )}
                <Button
                  fullWidth
                  sx={{ mt: 2 }}
                  variant="outlined"
                  onClick={() => navigate('/hosts')}
                >
                  Go to Hosts
                </Button>
              </CardContent>
            </Card>
          </Grid>
        )}

        {stats?.vulnerability_stats && (
          <Grid item xs={12}>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom color="error">
                  Vulnerability Overview
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={2}>
                    <Box textAlign="center">
                      <Typography variant="h5" color="error.main">
                        {stats.vulnerability_stats.total_vulnerabilities}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Total Vulnerabilities
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <Box textAlign="center">
                      <Typography variant="h5" sx={{ color: '#d32f2f' }}>
                        {stats.vulnerability_stats.critical}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Critical
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <Box textAlign="center">
                      <Typography variant="h5" sx={{ color: '#f57c00' }}>
                        {stats.vulnerability_stats.high}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        High
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <Box textAlign="center">
                      <Typography variant="h5" sx={{ color: '#ffa000' }}>
                        {stats.vulnerability_stats.medium}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Medium
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <Box textAlign="center">
                      <Typography variant="h5" sx={{ color: '#388e3c' }}>
                        {stats.vulnerability_stats.low}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Low
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={2}>
                    <Box textAlign="center">
                      <Typography variant="h5" color="primary">
                        {stats.vulnerability_stats.hosts_with_vulnerabilities}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Affected Hosts
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        )}

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

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Vulnerability Hotspots
            </Typography>
            {vulnerabilityHotspots.length ? (
              <List dense sx={{ maxHeight: 320, overflow: 'auto' }}>
                {vulnerabilityHotspots.slice(0, 6).map((host) => (
                  <React.Fragment key={`hotspot-${host.host_id}`}>
                    <ListItem alignItems="flex-start">
                      <ListItemText
                        primary={
                          <Typography variant="body1" fontFamily="monospace">
                            {host.ip_address}
                          </Typography>
                        }
                        secondary={
                          <Box display="flex" gap={1} mt={1}>
                            <Chip label={`${host.critical} critical`} color="error" size="small" />
                            <Chip label={`${host.high} high`} color="warning" size="small" />
                            <Chip label={`${host.medium} medium`} color="info" size="small" />
                            <Chip label={`Score ${host.risk_score}`} size="small" />
                          </Box>
                        }
                      />
                    </ListItem>
                    <Divider component="li" />
                  </React.Fragment>
                ))}
              </List>
            ) : (
              <Typography color="text.secondary">No vulnerability hotspots identified.</Typography>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Ingestion Job Activity
              </Typography>
              {ingestionJobs.length ? (
                <List dense sx={{ maxHeight: 320, overflow: 'auto' }}>
                  {ingestionJobs.map((job) => (
                    <React.Fragment key={`job-${job.id}`}>
                      <ListItem alignItems="flex-start">
                        <ListItemText
                          primary={
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                              <Box>
                                <Typography variant="subtitle2">{job.original_filename}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                  Submitted {new Date(job.created_at).toLocaleString()}
                                </Typography>
                              </Box>
                              <Chip
                                label={job.status.toUpperCase()}
                                color={
                                  job.status === 'completed'
                                    ? 'success'
                                    : job.status === 'failed'
                                    ? 'error'
                                    : 'info'
                                }
                                size="small"
                              />
                            </Box>
                          }
                          secondary={
                            <Box mt={1}>
                              <Typography variant="body2" color="text.secondary">
                                {job.message || job.error_message || 'Processing pending…'}
                              </Typography>
                              {job.scan_id && (
                                <Button
                                  size="small"
                                  sx={{ mt: 0.5, pl: 0 }}
                                  onClick={() => navigate(`/scans/${job.scan_id}`)}
                                >
                                  View scan
                                </Button>
                              )}
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider component="li" />
                    </React.Fragment>
                  ))}
                </List>
              ) : (
                <Typography color="text.secondary">
                  No ingestion jobs have been queued yet. Upload a scan to see job activity here.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <RiskAssessmentWidget subnetStats={stats?.subnet_stats || []} />
        </Grid>

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
                        <TableCell align="right">Addresses</TableCell>
                        <TableCell align="right">Discovered</TableCell>
                        <TableCell align="right">Utilization</TableCell>
                        <TableCell>Risk Level</TableCell>
                        <TableCell>Network Type</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {stats.subnet_stats.map((subnet: SubnetStats) => (
                        <Tooltip title="Click to view hosts in this subnet" key={subnet.id}>
                          <TableRow
                            hover
                            sx={{
                              cursor: 'pointer',
                              '&:hover': {
                                backgroundColor: 'action.hover',
                              },
                            }}
                            onClick={() => handleSubnetClick(subnet)}
                          >
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
                            <TableCell align="right">
                              <Typography variant="body2">
                                {subnet.usable_addresses ? `${subnet.usable_addresses} usable` : 'N/A'}
                              </Typography>
                              {subnet.total_addresses && (
                                <Typography variant="caption" color="textSecondary">
                                  ({subnet.total_addresses} total)
                                </Typography>
                              )}
                            </TableCell>
                            <TableCell align="right">
                              <Chip
                                label={subnet.host_count}
                                color={subnet.host_count > 0 ? 'success' : 'default'}
                                size="small"
                              />
                            </TableCell>
                            <TableCell align="right">
                              {subnet.utilization_percentage !== undefined ? (
                                <Box display="flex" alignItems="center" justifyContent="flex-end">
                                  <Typography variant="body2" fontWeight="medium">
                                    {subnet.utilization_percentage.toFixed(1)}%
                                  </Typography>
                                </Box>
                              ) : (
                                <Typography variant="body2" color="textSecondary">N/A</Typography>
                              )}
                            </TableCell>
                            <TableCell>
                              {subnet.risk_level && (
                                <Chip
                                  label={subnet.risk_level.toUpperCase()}
                                  color={
                                    subnet.risk_level === 'critical'
                                      ? 'error'
                                      : subnet.risk_level === 'high'
                                      ? 'warning'
                                      : subnet.risk_level === 'medium'
                                      ? 'info'
                                      : subnet.risk_level === 'low'
                                      ? 'success'
                                      : 'default'
                                  }
                                  size="small"
                                  variant="outlined"
                                />
                              )}
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" color={subnet.is_private ? 'success.main' : 'warning.main'}>
                                {subnet.is_private ? 'Private' : 'Public'}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        </Tooltip>
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
                          <TableCell>{new Date(scan.created_at).toLocaleDateString()}</TableCell>
                          <TableCell>
                            {scan.up_hosts}/{scan.total_hosts}
                          </TableCell>
                          <TableCell>{scan.open_ports}</TableCell>
                          <TableCell>
                            <Chip
                              label={`${scan.up_hosts}/${scan.total_hosts} hosts up`}
                              color={
                                (() => {
                                  if (scan.total_hosts === 0) return 'default';
                                  const ratio = scan.up_hosts / (scan.total_hosts || 1);
                                  if (ratio > 0.8) return 'success';
                                  if (ratio > 0.5) return 'warning';
                                  return 'error';
                                })()
                              }
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
