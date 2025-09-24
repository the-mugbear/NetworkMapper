import React, { useEffect, useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Paper,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  IconButton,
  Alert,
  Badge,
  Divider,
  Stack,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  List,
  ListItem,
  ListItemText,
  Link,
} from '@mui/material';
import type { SelectChangeEvent } from '@mui/material/Select';
import {
  ArrowBack as BackIcon,
  ExpandMore as ExpandMoreIcon,
  Computer as ComputerIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Timeline as TimelineIcon,
  Visibility as VisibilityIcon,
  BookmarkAdded as BookmarkIcon,
  BookmarkBorder as BookmarkBorderIcon,
  NoteAdd as NoteAddIcon,
  DeleteOutline as DeleteIcon,
  Launch as LaunchIcon,
} from '@mui/icons-material';
import {
  getHost,
  getHostConflicts,
  followHost,
  unfollowHost,
  createHostNote,
  updateHostNote,
  deleteHostNote,
} from '../services/api';
import type {
  Host,
  HostConflict,
  FollowStatus,
  HostNote,
  NoteStatus,
  HostVulnerability,
} from '../services/api';
import HostRiskAnalysis from '../components/HostRiskAnalysis';
import { getHostWebLinks, HostWebLink } from '../utils/webLinks';

const FOLLOW_STATUS_ORDER: FollowStatus[] = ['watching', 'in_review', 'reviewed'];

const VULNERABILITY_PREVIEW_LIMIT = 10;

const VULNERABILITY_SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

const VULNERABILITY_CHIP_COLOR: Record<string, 'error' | 'warning' | 'info' | 'default' | 'success'> = {
  critical: 'error',
  high: 'warning',
  medium: 'warning',
  low: 'info',
  info: 'default',
  unknown: 'default',
};

const FOLLOW_STATUS_META: Record<FollowStatus, { label: string; description: string; chipColor: 'info' | 'warning' | 'success' }> = {
  watching: {
    label: 'Watching',
    description: 'Track this host for future review or to share with teammates.',
    chipColor: 'info',
  },
  in_review: {
    label: 'In Review',
    description: 'You are actively investigating this host and its findings.',
    chipColor: 'warning',
  },
  reviewed: {
    label: 'Reviewed',
    description: 'Investigation completed—leave a note with outcomes if relevant.',
    chipColor: 'success',
  },
};

const NOTE_STATUS_META: Record<NoteStatus, { label: string; chipColor: 'default' | 'info' | 'warning' | 'success' }> = {
  open: {
    label: 'Open',
    chipColor: 'info',
  },
  in_progress: {
    label: 'In Progress',
    chipColor: 'warning',
  },
  resolved: {
    label: 'Resolved',
    chipColor: 'success',
  },
};

export default function HostDetail() {
  const { hostId } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const [host, setHost] = useState<Host | null>(null);
  const [conflicts, setConflicts] = useState<HostConflict[]>([]);
  const [showConflicts, setShowConflicts] = useState(false);
  const [loading, setLoading] = useState(true);
  const [followStatus, setFollowStatus] = useState<FollowStatus | ''>('');
  const [followLoading, setFollowLoading] = useState(false);
  const [notes, setNotes] = useState<HostNote[]>([]);
  const [noteBody, setNoteBody] = useState('');
  const [noteStatus, setNoteStatus] = useState<NoteStatus>('open');
  const [noteSubmitting, setNoteSubmitting] = useState(false);
  const [noteError, setNoteError] = useState<string | null>(null);
  const [noteActionId, setNoteActionId] = useState<number | null>(null);
  const [showAllVulnerabilities, setShowAllVulnerabilities] = useState(false);
  const numericHostId = hostId ? parseInt(hostId, 10) : null;

  useEffect(() => {
    const fetchHost = async () => {
      if (!numericHostId) return;

      try {
        const [hostData, conflictData] = await Promise.all([
          getHost(numericHostId),
          getHostConflicts(numericHostId),
        ]);
        setHost(hostData);
        setConflicts(conflictData || []);
        setFollowStatus(hostData.follow?.status ?? '');
        setNotes(hostData.notes ?? []);
      } catch (error) {
        console.error('Error fetching host details:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchHost();
  }, [numericHostId]);

  const getStateColor = (state: string | null) => {
    switch (state) {
      case 'up': return 'success';
      case 'down': return 'error';
      case 'open': return 'success';
      case 'closed': return 'error';
      case 'filtered': return 'warning';
      default: return 'default';
    }
  };

  const getConfidenceColor = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 70) return 'warning';
    return 'error';
  };

  const formatConfidenceTooltip = (conflict: HostConflict) => {
    return `Confidence: ${conflict.confidence_score}% | Source: ${conflict.scan_type} | Method: ${conflict.method}`;
  };

  const updateFollow = async (status: FollowStatus | 'none') => {
    if (!numericHostId) return;
    setFollowLoading(true);
    try {
      if (status === 'none') {
        await unfollowHost(numericHostId);
        setFollowStatus('');
        setHost((previous) => (previous ? { ...previous, follow: null } : previous));
      } else {
        const response = await followHost(numericHostId, status);
        setFollowStatus(response.status);
        setHost((previous) => (previous ? { ...previous, follow: response } : previous));
      }
    } catch (error) {
      console.error('Failed to update follow status:', error);
    } finally {
      setFollowLoading(false);
    }
  };

  const handleFollowSelectChange = (event: SelectChangeEvent<string>) => {
    const value = event.target.value as FollowStatus | 'none';
    updateFollow(value);
  };

  const handleNoteBodyChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (noteError) {
      setNoteError(null);
    }
    setNoteBody(event.target.value);
  };

  const handleNoteStatusChange = (event: SelectChangeEvent<NoteStatus>) => {
    setNoteStatus(event.target.value as NoteStatus);
  };

  const handleCreateNote = async () => {
    if (!numericHostId) return;
    if (!noteBody.trim()) {
      setNoteError('Add a short note before saving.');
      return;
    }

    setNoteSubmitting(true);
    try {
      const response = await createHostNote(numericHostId, {
        body: noteBody.trim(),
        status: noteStatus,
      });
      setNotes((previous) => [response, ...previous]);
      setHost((previous) => (previous ? { ...previous, notes: [response, ...(previous.notes ?? [])] } : previous));
      setNoteBody('');
      setNoteStatus('open');
      setNoteError(null);
    } catch (error) {
      console.error('Failed to save note:', error);
      setNoteError('Unable to save note right now. Please try again.');
    } finally {
      setNoteSubmitting(false);
    }
  };

  const handleDeleteNote = async (noteId: number) => {
    if (!numericHostId) return;
    setNoteActionId(noteId);
    try {
      await deleteHostNote(numericHostId, noteId);
      setNotes((previous) => previous.filter((note) => note.id !== noteId));
      setHost((previous) =>
        previous
          ? { ...previous, notes: (previous.notes ?? []).filter((note) => note.id !== noteId) }
          : previous
      );
    } catch (error) {
      console.error('Failed to delete note:', error);
    } finally {
      setNoteActionId(null);
    }
  };

  const handleUpdateNoteStatus = async (noteId: number, status: NoteStatus) => {
    if (!numericHostId) return;
    setNoteActionId(noteId);
    try {
      const response = await updateHostNote(numericHostId, noteId, { status });
      setNotes((previous) => previous.map((note) => (note.id === noteId ? response : note)));
      setHost((previous) =>
        previous
          ? {
              ...previous,
              notes: (previous.notes ?? []).map((note) => (note.id === noteId ? response : note)),
            }
          : previous
      );
    } catch (error) {
      console.error('Failed to update note status:', error);
    } finally {
      setNoteActionId(null);
    }
  };

  const hasConflicts = conflicts.length > 0;
  const conflictsByField = conflicts.reduce((acc, conflict) => {
    if (!acc[conflict.field_name]) acc[conflict.field_name] = [];
    acc[conflict.field_name].push(conflict);
    return acc;
  }, {} as Record<string, HostConflict[]>);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <Typography>Loading host details...</Typography>
      </Box>
    );
  }

  const webLinks = useMemo<HostWebLink[]>(() => (host ? getHostWebLinks(host) : []), [host]);
  if (!host) {
    return (
      <Box textAlign="center" py={8}>
        <Typography variant="h6" color="error">
          Host not found
        </Typography>
        <Button onClick={() => navigate('/hosts')} sx={{ mt: 2 }}>
          Back to Hosts
        </Button>
      </Box>
    );
  }

  const openPorts = host.ports.filter(port => port.state === 'open');
  const closedPorts = host.ports.filter(port => port.state === 'closed');
  const filteredPorts = host.ports.filter(port => port.state === 'filtered');
  const followInfo = host.follow;
  const followSelectValue = followStatus || 'none';
  const followHelperText = followStatus
    ? FOLLOW_STATUS_META[followStatus].description
    : 'Select a review status to keep track of this host.';
  const followChipColor = followStatus ? FOLLOW_STATUS_META[followStatus].chipColor : 'default';
  const noteList = notes;
  const primaryWebLink = webLinks[0] ?? null;

  return (
    <Box>
      <Box display="flex" alignItems="center" justifyContent="space-between" mb={3}>
        <Box display="flex" alignItems="center">
          <Button
            startIcon={<BackIcon />}
            onClick={() => navigate('/hosts')}
            sx={{ mr: 2 }}
          >
            Back to Hosts
          </Button>
          <ComputerIcon sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h4">
            {primaryWebLink ? (
              <Link
                href={primaryWebLink.url}
                target="_blank"
                rel="noopener noreferrer"
                underline="hover"
                sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75 }}
              >
                {host.ip_address}
                <LaunchIcon sx={{ fontSize: '1.5rem' }} />
              </Link>
            ) : (
              host.ip_address
            )}
          </Typography>
          {hasConflicts && (
            <Tooltip title={`${conflicts.length} data conflicts detected`}>
              <Badge badgeContent={conflicts.length} color="warning" sx={{ ml: 2 }}>
                <WarningIcon color="warning" />
              </Badge>
            </Tooltip>
          )}
        </Box>

        <Box display="flex" gap={1}>
          {hasConflicts && (
            <Button
              variant={showConflicts ? 'contained' : 'outlined'}
              startIcon={showConflicts ? <VisibilityIcon /> : <TimelineIcon />}
              onClick={() => setShowConflicts(!showConflicts)}
              color="warning"
            >
              {showConflicts ? 'Hide' : 'Show'} Conflicts
            </Button>
          )}
        </Box>
      </Box>

      {webLinks.length > 1 && (
        <Stack direction="row" spacing={1} mb={3}>
          {webLinks.map((link) => (
            <Chip
              key={link.url}
              icon={<LaunchIcon sx={{ fontSize: '1rem' }} />}
              component="a"
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              label={`${link.protocol.toUpperCase()} ${link.port}`}
              clickable
              variant="outlined"
            />
          ))}
        </Stack>
      )}

      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Stack spacing={2}>
                <Box display="flex" alignItems="center" gap={1}>
                  {followStatus ? (
                    <BookmarkIcon
                      color={
                        followChipColor === 'success'
                          ? 'success'
                          : followChipColor === 'warning'
                          ? 'warning'
                          : 'info'
                      }
                    />
                  ) : (
                    <BookmarkBorderIcon color="disabled" />
                  )}
                  <Typography variant="h6">Review Status</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {followHelperText}
                </Typography>
                <FormControl fullWidth size="small">
                  <InputLabel id="follow-status-label">Follow Status</InputLabel>
                  <Select
                    labelId="follow-status-label"
                    value={followSelectValue}
                    label="Follow Status"
                    onChange={handleFollowSelectChange}
                    disabled={followLoading}
                  >
                    <MenuItem value="none">
                      <em>Not Following</em>
                    </MenuItem>
                    {FOLLOW_STATUS_ORDER.map((status) => (
                      <MenuItem key={status} value={status}>
                        {FOLLOW_STATUS_META[status].label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Chip
                    label={
                      followStatus
                        ? FOLLOW_STATUS_META[followStatus].label
                        : 'Not Following'
                    }
                    color={followChipColor}
                    size="small"
                  />
                  {followInfo && (
                    <Typography variant="caption" color="text.secondary">
                      Updated{' '}
                      {new Date(followInfo.updated_at ?? followInfo.created_at).toLocaleString()}
                    </Typography>
                  )}
                </Stack>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Stack spacing={2}>
                <Box display="flex" alignItems="center" gap={1}>
                  <NoteAddIcon color="primary" />
                  <Typography variant="h6">Add Investigation Note</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Capture observations, remediation actions, or handoff context for teammates.
                </Typography>
                {noteError && (
                  <Alert severity="error" onClose={() => setNoteError(null)}>
                    {noteError}
                  </Alert>
                )}
                <TextField
                  label="Note"
                  placeholder="Example: Confirmed port 445 is exposed; scheduling remediation."
                  value={noteBody}
                  onChange={handleNoteBodyChange}
                  multiline
                  minRows={3}
                  fullWidth
                  disabled={noteSubmitting}
                />
                <Stack
                  direction={{ xs: 'column', sm: 'row' }}
                  spacing={2}
                  alignItems={{ xs: 'stretch', sm: 'center' }}
                >
                  <FormControl sx={{ minWidth: 160 }} size="small">
                    <InputLabel id="note-status-label">Status</InputLabel>
                    <Select
                      labelId="note-status-label"
                      value={noteStatus}
                      label="Status"
                      onChange={handleNoteStatusChange}
                      disabled={noteSubmitting}
                    >
                      {Object.entries(NOTE_STATUS_META).map(([value, meta]) => (
                        <MenuItem key={value} value={value}>
                          {meta.label}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  <Box flexGrow={1} />
                  <Button
                    variant="contained"
                    startIcon={<NoteAddIcon />}
                    onClick={handleCreateNote}
                    disabled={noteSubmitting}
                  >
                    {noteSubmitting ? 'Saving…' : 'Save Note'}
                  </Button>
                </Stack>
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Team Notes</Typography>
            <Chip label={`${noteList.length}`} variant="outlined" size="small" />
          </Box>
          {noteList.length ? (
            <List disablePadding>
              {noteList.map((note, index) => {
                const statusMeta = NOTE_STATUS_META[note.status];
                const authorLabel = note.author_name || 'Unknown analyst';
                return (
                  <React.Fragment key={note.id}>
                    <ListItem
                      alignItems="flex-start"
                      sx={{ flexDirection: 'column', alignItems: 'stretch', gap: 1 }}
                    >
                      <Box display="flex" justifyContent="space-between" width="100%" flexWrap="wrap" gap={1}>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Chip label={statusMeta.label} color={statusMeta.chipColor} size="small" />
                          <Typography variant="body2" color="text.secondary">
                            {authorLabel}
                          </Typography>
                        </Stack>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <FormControl size="small" sx={{ minWidth: 150 }}>
                            <InputLabel id={`note-status-${note.id}`}>Status</InputLabel>
                            <Select
                              labelId={`note-status-${note.id}`}
                              value={note.status}
                              label="Status"
                              onChange={(event) =>
                                handleUpdateNoteStatus(note.id, event.target.value as NoteStatus)
                              }
                              disabled={noteActionId === note.id}
                            >
                              {Object.entries(NOTE_STATUS_META).map(([value, meta]) => (
                                <MenuItem key={value} value={value}>
                                  {meta.label}
                                </MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                          <Tooltip title="Delete note">
                            <span>
                              <IconButton
                                edge="end"
                                aria-label="delete note"
                                onClick={() => handleDeleteNote(note.id)}
                                disabled={noteActionId === note.id}
                              >
                                <DeleteIcon />
                              </IconButton>
                            </span>
                          </Tooltip>
                        </Stack>
                      </Box>
                      <ListItemText
                        primary={
                          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                            {note.body}
                          </Typography>
                        }
                        secondary={
                          <Typography variant="caption" color="text.secondary">
                            Logged {new Date(note.created_at).toLocaleString()}
                            {note.updated_at &&
                              ` · Updated ${new Date(note.updated_at).toLocaleString()}`}
                          </Typography>
                        }
                      />
                    </ListItem>
                    {index < noteList.length - 1 && <Divider component="li" />}
                  </React.Fragment>
                );
              })}
            </List>
          ) : (
            <Typography color="text.secondary">
              No notes yet—add your first observation to start a review trail.
            </Typography>
          )}
        </CardContent>
      </Card>

      {totalVulnerabilities > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6" color="error">
                Vulnerabilities
              </Typography>
              <Chip label={`${totalVulnerabilities}`} color="error" size="small" />
            </Box>
            <Stack spacing={2}>
              {displayedVulnerabilities.map((vuln) => {
                const severityKey = (vuln.severity ?? 'unknown').toLowerCase();
                const chipColor = VULNERABILITY_CHIP_COLOR[severityKey] ?? 'default';
                const title = vuln.title || vuln.plugin_id || 'Unnamed finding';
                const cveLink = vuln.cve_id
                  ? `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve_id}`
                  : null;

                return (
                  <Box
                    key={`${vuln.id}-${vuln.plugin_id}-${vuln.port_number ?? 'host'}`}
                    display="flex"
                    alignItems="flex-start"
                    gap={2}
                    sx={{ borderBottom: '1px solid', borderColor: 'divider', pb: 1, '&:last-of-type': { borderBottom: 'none', pb: 0 } }}
                  >
                    <Box flex={1}>
                      <Typography variant="subtitle2" gutterBottom>
                        {title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {(vuln.source ? vuln.source.toUpperCase() : 'Unknown source')}
                        {vuln.cvss_score !== null && vuln.cvss_score !== undefined && ` · CVSS ${vuln.cvss_score}`}
                        {cveLink && (
                          <>
                            {' · '}
                            <Link href={cveLink} target="_blank" rel="noopener noreferrer" underline="hover">
                              {vuln.cve_id}
                            </Link>
                          </>
                        )}
                      </Typography>
                      {vuln.port_number && (
                        <Typography variant="body2" color="text.secondary">
                          Port {vuln.port_number}/{(vuln.protocol ?? '').toUpperCase() || 'TCP'}
                          {vuln.service_name && ` • ${vuln.service_name}`}
                        </Typography>
                      )}
                      {vuln.solution && (
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                          {vuln.solution.length > 220 ? `${vuln.solution.slice(0, 220)}…` : vuln.solution}
                        </Typography>
                      )}
                      {vuln.last_seen && (
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                          Last seen {new Date(vuln.last_seen).toLocaleString()}
                        </Typography>
                      )}
                    </Box>
                    <Chip
                      label={(vuln.severity ?? 'unknown').toUpperCase()}
                      color={chipColor}
                      size="small"
                      icon={<SecurityIcon fontSize="small" />}
                    />
                  </Box>
                );
              })}
            </Stack>
            {totalVulnerabilities > VULNERABILITY_PREVIEW_LIMIT && (
              <Box display="flex" justifyContent="flex-end" mt={2}>
                <Button size="small" onClick={() => setShowAllVulnerabilities((prev) => !prev)}>
                  {showAllVulnerabilities ? 'Show fewer findings' : `Show all findings (${totalVulnerabilities})`}
                </Button>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {/* Host Information */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Host Information
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    IP Address
                  </Typography>
                  <Typography variant="body1">
                    {host.ip_address}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Hostname
                        {conflictsByField.hostname && (
                          <Tooltip title={formatConfidenceTooltip(conflictsByField.hostname[0])}>
                            <InfoIcon fontSize="small" color="info" sx={{ ml: 0.5 }} />
                          </Tooltip>
                        )}
                      </Typography>
                      <Typography variant="body1">
                        {host.hostname || 'N/A'}
                      </Typography>
                    </Box>
                    {conflictsByField.hostname && showConflicts && (
                      <Chip
                        size="small"
                        label={`${conflictsByField.hostname[0].confidence_score}%`}
                        color={getConfidenceColor(conflictsByField.hostname[0].confidence_score)}
                      />
                    )}
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        State
                        {conflictsByField.state && (
                          <Tooltip title={formatConfidenceTooltip(conflictsByField.state[0])}>
                            <InfoIcon fontSize="small" color="info" sx={{ ml: 0.5 }} />
                          </Tooltip>
                        )}
                      </Typography>
                      <Chip
                        label={host.state || 'unknown'}
                        color={getStateColor(host.state)}
                        size="small"
                      />
                    </Box>
                    {conflictsByField.state && showConflicts && (
                      <Chip
                        size="small"
                        label={`${conflictsByField.state[0].confidence_score}%`}
                        color={getConfidenceColor(conflictsByField.state[0].confidence_score)}
                      />
                    )}
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Operating System
                        {conflictsByField.os_name && (
                          <Tooltip title={formatConfidenceTooltip(conflictsByField.os_name[0])}>
                            <InfoIcon fontSize="small" color="info" sx={{ ml: 0.5 }} />
                          </Tooltip>
                        )}
                      </Typography>
                      <Typography variant="body1">
                        {host.os_name || 'Unknown'}
                      </Typography>
                    </Box>
                    {conflictsByField.os_name && showConflicts && (
                      <Chip
                        size="small"
                        label={`${conflictsByField.os_name[0].confidence_score}%`}
                        color={getConfidenceColor(conflictsByField.os_name[0].confidence_score)}
                      />
                    )}
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          {/* Vulnerability Summary */}
          {host.vulnerability_summary && host.vulnerability_summary.total_vulnerabilities > 0 && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom color="error">
                  Vulnerability Summary
                </Typography>
                <Box display="flex" flexDirection="column" gap={1}>
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2">Critical:</Typography>
                    <Chip
                      label={host.vulnerability_summary.critical}
                      sx={{ backgroundColor: '#d32f2f', color: 'white' }}
                      size="small"
                    />
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2">High:</Typography>
                    <Chip
                      label={host.vulnerability_summary.high}
                      sx={{ backgroundColor: '#f57c00', color: 'white' }}
                      size="small"
                    />
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2">Medium:</Typography>
                    <Chip
                      label={host.vulnerability_summary.medium}
                      sx={{ backgroundColor: '#ffa000', color: 'white' }}
                      size="small"
                    />
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2">Low:</Typography>
                    <Chip
                      label={host.vulnerability_summary.low}
                      sx={{ backgroundColor: '#388e3c', color: 'white' }}
                      size="small"
                    />
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2">Info:</Typography>
                    <Chip
                      label={host.vulnerability_summary.info}
                      color="primary"
                      size="small"
                    />
                  </Box>
                  <Divider sx={{ my: 1 }} />
                  <Box display="flex" justifyContent="space-between" pt={1}>
                    <Typography variant="body2"><strong>Total:</strong></Typography>
                    <Typography variant="body2" color="error">
                      <strong>{host.vulnerability_summary.total_vulnerabilities}</strong>
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Port Summary
              </Typography>
              <Box display="flex" flexDirection="column" gap={1}>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Open:</Typography>
                  <Chip label={openPorts.length} color="success" size="small" />
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Closed:</Typography>
                  <Chip label={closedPorts.length} color="error" size="small" />
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Filtered:</Typography>
                  <Chip label={filteredPorts.length} color="warning" size="small" />
                </Box>
                <Box display="flex" justifyContent="space-between" pt={1}>
                  <Typography variant="body2"><strong>Total:</strong></Typography>
                  <Typography variant="body2"><strong>{host.ports.length}</strong></Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Risk Analysis Section */}
      {numericHostId !== null && <HostRiskAnalysis hostId={numericHostId} />}

      {/* Conflicts Section */}
      {showConflicts && hasConflicts && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              <WarningIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Data Conflicts & Confidence
            </Typography>
            <Alert severity="info" sx={{ mb: 2 }}>
              This host has conflicting information from different scans. The displayed values represent the highest confidence data.
            </Alert>

            {Object.entries(conflictsByField).map(([fieldName, fieldConflicts]) => (
              <Box key={fieldName} sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1, textTransform: 'capitalize' }}>
                  {fieldName.replace('_', ' ')}
                </Typography>
                <Grid container spacing={1}>
                  {fieldConflicts.map((conflict, index) => (
                    <Grid item key={index}>
                      <Tooltip title={`${conflict.scan_type} | ${conflict.method} | Scan ID: ${conflict.scan_id}`}>
                        <Chip
                          label={`${conflict.confidence_score}% - ${conflict.scan_type}`}
                          color={getConfidenceColor(conflict.confidence_score)}
                          size="small"
                          variant={index === 0 ? 'filled' : 'outlined'}
                        />
                      </Tooltip>
                    </Grid>
                  ))}
                </Grid>
                {fieldConflicts.length > 1 && (
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                    {fieldConflicts.length} different values detected across scans
                  </Typography>
                )}
                <Divider sx={{ mt: 1 }} />
              </Box>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Ports Details */}
      <Paper>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>
            <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Port Details
          </Typography>

          {/* Open Ports */}
          {openPorts.length > 0 && (
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">
                  Open Ports ({openPorts.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>Version</TableCell>
                        <TableCell>State</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {openPorts.map((port) => (
                        <TableRow key={port.id}>
                          <TableCell>{port.port_number}</TableCell>
                          <TableCell>{port.protocol}</TableCell>
                          <TableCell>{port.service_name || 'Unknown'}</TableCell>
                          <TableCell>
                            {port.service_product && port.service_version
                              ? `${port.service_product} ${port.service_version}`
                              : port.service_product || 'N/A'
                            }
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={port.state || 'unknown'}
                              color={getStateColor(port.state)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Closed Ports */}
          {closedPorts.length > 0 && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">
                  Closed Ports ({closedPorts.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>State</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {closedPorts.map((port) => (
                        <TableRow key={port.id}>
                          <TableCell>{port.port_number}</TableCell>
                          <TableCell>{port.protocol}</TableCell>
                          <TableCell>{port.service_name || 'Unknown'}</TableCell>
                          <TableCell>
                            <Chip
                              label={port.state || 'unknown'}
                              color={getStateColor(port.state)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Filtered Ports */}
          {filteredPorts.length > 0 && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">
                  Filtered Ports ({filteredPorts.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>State</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {filteredPorts.map((port) => (
                        <TableRow key={port.id}>
                          <TableCell>{port.port_number}</TableCell>
                          <TableCell>{port.protocol}</TableCell>
                          <TableCell>{port.service_name || 'Unknown'}</TableCell>
                          <TableCell>
                            <Chip
                              label={port.state || 'unknown'}
                              color={getStateColor(port.state)}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          )}
        </Box>
      </Paper>
    </Box>
  );
}
