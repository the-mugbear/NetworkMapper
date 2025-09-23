import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Grid,
  TextField,
  Button,
  Card,
  CardContent,
  CardActions,
  Divider,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip
} from '@mui/material';
import {
  Save,
  Lock,
  Security,
  History,
  Delete,
  Visibility
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import apiClient from '../services/api';

interface UserSession {
  id: number;
  ip_address: string;
  user_agent: string;
  created_at: string;
  last_activity: string;
  expires_at: string;
}

const Profile: React.FC = () => {
  const { user, updateUser } = useAuth();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Profile form state
  const [profileForm, setProfileForm] = useState({
    email: user?.email || '',
    full_name: user?.full_name || ''
  });

  // Password form state
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: ''
  });

  // Sessions
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(true);

  // Password dialog
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);

  useEffect(() => {
    loadSessions();
  }, []);

  const loadSessions = async () => {
    try {
      const response = await apiClient.get('/auth/sessions');
      setSessions(response.data);
    } catch (error) {
      console.error('Failed to load sessions:', error);
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleProfileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setMessage(null);

    try {
      await apiClient.put('/users/profile', profileForm);

      // Update user context
      if (user) {
        updateUser({
          ...user,
          email: profileForm.email,
          full_name: profileForm.full_name
        });
      }

      setMessage({ type: 'success', text: 'Profile updated successfully!' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to update profile'
      });
    } finally {
      setSaving(false);
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setMessage({ type: 'error', text: 'New passwords do not match' });
      return;
    }

    setSaving(true);
    setMessage(null);

    try {
      await apiClient.post('/auth/change-password', {
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password
      });

      setPasswordForm({
        current_password: '',
        new_password: '',
        confirm_password: ''
      });
      setPasswordDialogOpen(false);
      setMessage({ type: 'success', text: 'Password changed successfully!' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to change password'
      });
    } finally {
      setSaving(false);
    }
  };

  const handleRevokeSession = async (sessionId: number) => {
    try {
      await apiClient.delete(`/auth/sessions/${sessionId}`);
      setSessions(sessions.filter(s => s.id !== sessionId));
      setMessage({ type: 'success', text: 'Session revoked successfully' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to revoke session'
      });
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getRoleColor = (role: string): "error" | "warning" | "info" | "success" | "default" => {
    switch (role) {
      case 'admin': return 'error';
      case 'analyst': return 'warning';
      case 'auditor': return 'info';
      case 'viewer': return 'success';
      default: return 'default';
    }
  };

  if (!user) {
    return (
      <Container maxWidth="md">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="md">
      <Box py={3}>
        <Typography variant="h4" gutterBottom>
          User Profile
        </Typography>

        {message && (
          <Alert severity={message.type} sx={{ mb: 2 }} onClose={() => setMessage(null)}>
            {message.text}
          </Alert>
        )}

        <Grid container spacing={3}>
          {/* User Info Card */}
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box display="flex" flexDirection="column" alignItems="center" textAlign="center">
                  <Box
                    sx={{
                      width: 80,
                      height: 80,
                      borderRadius: '50%',
                      bgcolor: 'primary.main',
                      color: 'white',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '2rem',
                      fontWeight: 'bold',
                      mb: 2
                    }}
                  >
                    {user.username.charAt(0).toUpperCase()}
                  </Box>

                  <Typography variant="h6" gutterBottom>
                    {user.full_name || user.username}
                  </Typography>

                  <Chip
                    label={user.role.toUpperCase()}
                    color={getRoleColor(user.role)}
                    size="small"
                    sx={{ mb: 1 }}
                  />

                  <Typography variant="body2" color="text.secondary">
                    Member since {formatDate(user.created_at || new Date().toISOString())}
                  </Typography>

                  {user.last_login && (
                    <Typography variant="body2" color="text.secondary">
                      Last login: {formatDate(user.last_login)}
                    </Typography>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Profile Form */}
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Profile Information
                </Typography>

                <Box component="form" onSubmit={handleProfileSubmit}>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        label="Username"
                        value={user.username}
                        disabled
                        helperText="Username cannot be changed"
                      />
                    </Grid>

                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        label="Email"
                        type="email"
                        value={profileForm.email}
                        onChange={(e) => setProfileForm({
                          ...profileForm,
                          email: e.target.value
                        })}
                        required
                      />
                    </Grid>

                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        label="Full Name"
                        value={profileForm.full_name}
                        onChange={(e) => setProfileForm({
                          ...profileForm,
                          full_name: e.target.value
                        })}
                      />
                    </Grid>
                  </Grid>
                </Box>
              </CardContent>

              <CardActions>
                <Button
                  type="submit"
                  variant="contained"
                  startIcon={saving ? <CircularProgress size={16} /> : <Save />}
                  disabled={saving}
                  onClick={handleProfileSubmit}
                >
                  {saving ? 'Saving...' : 'Save Changes'}
                </Button>

                <Button
                  variant="outlined"
                  startIcon={<Lock />}
                  onClick={() => setPasswordDialogOpen(true)}
                >
                  Change Password
                </Button>
              </CardActions>
            </Card>
          </Grid>

          {/* Active Sessions */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  <Security sx={{ mr: 1 }} />
                  Active Sessions
                </Typography>

                {sessionsLoading ? (
                  <Box display="flex" justifyContent="center" py={2}>
                    <CircularProgress size={24} />
                  </Box>
                ) : sessions.length === 0 ? (
                  <Typography color="text.secondary">
                    No active sessions found
                  </Typography>
                ) : (
                  <List>
                    {sessions.map((session, index) => (
                      <React.Fragment key={session.id}>
                        <ListItem>
                          <ListItemText
                            primary={
                              <Box>
                                <Typography variant="body2">
                                  {session.ip_address}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {session.user_agent.substring(0, 80)}...
                                </Typography>
                              </Box>
                            }
                            secondary={
                              <Box mt={1}>
                                <Typography variant="caption" display="block">
                                  Created: {formatDate(session.created_at)}
                                </Typography>
                                <Typography variant="caption" display="block">
                                  Last Active: {formatDate(session.last_activity)}
                                </Typography>
                                <Typography variant="caption" display="block">
                                  Expires: {formatDate(session.expires_at)}
                                </Typography>
                              </Box>
                            }
                          />
                          <ListItemSecondaryAction>
                            <IconButton
                              edge="end"
                              onClick={() => handleRevokeSession(session.id)}
                              color="error"
                            >
                              <Delete />
                            </IconButton>
                          </ListItemSecondaryAction>
                        </ListItem>
                        {index < sessions.length - 1 && <Divider />}
                      </React.Fragment>
                    ))}
                  </List>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Password Change Dialog */}
        <Dialog
          open={passwordDialogOpen}
          onClose={() => setPasswordDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Change Password</DialogTitle>
          <DialogContent>
            <Box component="form" onSubmit={handlePasswordSubmit} sx={{ mt: 1 }}>
              <TextField
                fullWidth
                type="password"
                label="Current Password"
                value={passwordForm.current_password}
                onChange={(e) => setPasswordForm({
                  ...passwordForm,
                  current_password: e.target.value
                })}
                margin="normal"
                required
              />

              <TextField
                fullWidth
                type="password"
                label="New Password"
                value={passwordForm.new_password}
                onChange={(e) => setPasswordForm({
                  ...passwordForm,
                  new_password: e.target.value
                })}
                margin="normal"
                required
                helperText="Password must be at least 8 characters"
              />

              <TextField
                fullWidth
                type="password"
                label="Confirm New Password"
                value={passwordForm.confirm_password}
                onChange={(e) => setPasswordForm({
                  ...passwordForm,
                  confirm_password: e.target.value
                })}
                margin="normal"
                required
              />
            </Box>
          </DialogContent>

          <DialogActions>
            <Button onClick={() => setPasswordDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handlePasswordSubmit}
              variant="contained"
              disabled={saving}
              startIcon={saving ? <CircularProgress size={16} /> : <Lock />}
            >
              {saving ? 'Changing...' : 'Change Password'}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
};

export default Profile;