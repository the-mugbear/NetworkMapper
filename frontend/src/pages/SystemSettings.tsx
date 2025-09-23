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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Alert,
  CircularProgress,
  Chip,
  Menu,
  ListItemIcon,
  ListItemText,
  Tooltip
} from '@mui/material';
import {
  Add,
  Edit,
  Delete,
  MoreVert,
  Security,
  AdminPanelSettings,
  Person,
  Visibility as ViewerIcon,
  Analytics as AnalystIcon,
  Assessment as AuditorIcon,
  Lock,
  CheckCircle,
  Cancel
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import apiClient from '../services/api';

interface User {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  last_login: string | null;
  created_at: string;
  created_by_id: number | null;
}

interface NewUserForm {
  username: string;
  email: string;
  password: string;
  full_name: string;
}

interface EditUserForm {
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
}

const SystemSettings: React.FC = () => {
  const { user: currentUser, hasPermission } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Dialogs
  const [newUserDialogOpen, setNewUserDialogOpen] = useState(false);
  const [editUserDialogOpen, setEditUserDialogOpen] = useState(false);
  const [resetPasswordDialogOpen, setResetPasswordDialogOpen] = useState(false);
  const [deleteUserDialogOpen, setDeleteUserDialogOpen] = useState(false);

  // Forms
  const [newUserForm, setNewUserForm] = useState<NewUserForm>({
    username: '',
    email: '',
    password: '',
    full_name: ''
  });

  const [editUserForm, setEditUserForm] = useState<EditUserForm>({
    email: '',
    full_name: '',
    role: 'viewer',
    is_active: true
  });

  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [newPassword, setNewPassword] = useState('');

  // Menu
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [menuUser, setMenuUser] = useState<User | null>(null);

  useEffect(() => {
    if (!hasPermission('admin')) {
      setMessage({ type: 'error', text: 'Access denied. Admin privileges required.' });
      return;
    }
    loadUsers();
  }, [hasPermission]);

  const loadUsers = async () => {
    try {
      const response = await apiClient.get('/users/');
      setUsers(response.data);
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to load users'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateUser = async () => {
    setSaving(true);
    setMessage(null);

    try {
      const response = await apiClient.post('/auth/register', newUserForm);
      setUsers([...users, response.data]);
      setNewUserDialogOpen(false);
      setNewUserForm({ username: '', email: '', password: '', full_name: '' });
      setMessage({ type: 'success', text: 'User created successfully!' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to create user'
      });
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateUser = async () => {
    if (!selectedUser) return;

    setSaving(true);
    setMessage(null);

    try {
      const response = await apiClient.put(`/users/${selectedUser.id}`, editUserForm);
      setUsers(users.map(u => u.id === selectedUser.id ? response.data : u));
      setEditUserDialogOpen(false);
      setMessage({ type: 'success', text: 'User updated successfully!' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to update user'
      });
    } finally {
      setSaving(false);
    }
  };

  const handleResetPassword = async () => {
    if (!selectedUser) return;

    setSaving(true);
    setMessage(null);

    try {
      await apiClient.post(`/users/${selectedUser.id}/reset-password`, {
        new_password: newPassword
      });
      setResetPasswordDialogOpen(false);
      setNewPassword('');
      setMessage({ type: 'success', text: 'Password reset successfully!' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to reset password'
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteUser = async () => {
    if (!selectedUser) return;

    setSaving(true);
    setMessage(null);

    try {
      await apiClient.delete(`/users/${selectedUser.id}`);
      setUsers(users.filter(u => u.id !== selectedUser.id));
      setDeleteUserDialogOpen(false);
      setMessage({ type: 'success', text: 'User deleted successfully!' });
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to delete user'
      });
    } finally {
      setSaving(false);
    }
  };

  const openEditDialog = (user: User) => {
    setSelectedUser(user);
    setEditUserForm({
      email: user.email,
      full_name: user.full_name || '',
      role: user.role,
      is_active: user.is_active
    });
    setEditUserDialogOpen(true);
    handleCloseMenu();
  };

  const openResetPasswordDialog = (user: User) => {
    setSelectedUser(user);
    setResetPasswordDialogOpen(true);
    handleCloseMenu();
  };

  const openDeleteDialog = (user: User) => {
    setSelectedUser(user);
    setDeleteUserDialogOpen(true);
    handleCloseMenu();
  };

  const handleMenuClick = (event: React.MouseEvent<HTMLElement>, user: User) => {
    setAnchorEl(event.currentTarget);
    setMenuUser(user);
  };

  const handleCloseMenu = () => {
    setAnchorEl(null);
    setMenuUser(null);
  };

  const getRoleIcon = (role: string) => {
    switch (role) {
      case 'admin':
        return <AdminPanelSettings fontSize="small" color="error" />;
      case 'analyst':
        return <AnalystIcon fontSize="small" color="warning" />;
      case 'auditor':
        return <AuditorIcon fontSize="small" color="info" />;
      case 'viewer':
        return <ViewerIcon fontSize="small" color="success" />;
      default:
        return <Person fontSize="small" />;
    }
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

  const formatDate = (dateString: string | null) => {
    return dateString ? new Date(dateString).toLocaleString() : 'Never';
  };

  if (!hasPermission('admin')) {
    return (
      <Container maxWidth="lg">
        <Box py={3}>
          <Alert severity="error">
            Access denied. Administrator privileges required.
          </Alert>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg">
      <Box py={3}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h4">
            <Security sx={{ mr: 1 }} />
            System Settings
          </Typography>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setNewUserDialogOpen(true)}
          >
            Add User
          </Button>
        </Box>

        {message && (
          <Alert severity={message.type} sx={{ mb: 2 }} onClose={() => setMessage(null)}>
            {message.text}
          </Alert>
        )}

        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              User Management
            </Typography>

            {loading ? (
              <Box display="flex" justifyContent="center" py={4}>
                <CircularProgress />
              </Box>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>User</TableCell>
                      <TableCell>Email</TableCell>
                      <TableCell>Role</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Last Login</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {users.map((user) => (
                      <TableRow key={user.id}>
                        <TableCell>
                          <Box display="flex" alignItems="center">
                            <Box
                              sx={{
                                width: 32,
                                height: 32,
                                borderRadius: '50%',
                                bgcolor: 'primary.main',
                                color: 'white',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontSize: '0.875rem',
                                fontWeight: 'bold',
                                mr: 2
                              }}
                            >
                              {user.username.charAt(0).toUpperCase()}
                            </Box>
                            <Box>
                              <Typography variant="body2" fontWeight="medium">
                                {user.full_name || user.username}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                @{user.username}
                              </Typography>
                            </Box>
                          </Box>
                        </TableCell>
                        <TableCell>{user.email}</TableCell>
                        <TableCell>
                          <Chip
                            icon={getRoleIcon(user.role)}
                            label={user.role.toUpperCase()}
                            size="small"
                            color={getRoleColor(user.role)}
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            icon={user.is_active ? <CheckCircle /> : <Cancel />}
                            label={user.is_active ? 'Active' : 'Inactive'}
                            size="small"
                            color={user.is_active ? 'success' : 'error'}
                            variant={user.is_active ? 'filled' : 'outlined'}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {formatDate(user.last_login)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {formatDate(user.created_at)}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <IconButton
                            onClick={(e) => handleMenuClick(e, user)}
                            disabled={user.id === currentUser?.id && (user.role === 'admin' || !user.is_active)}
                          >
                            <MoreVert />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>

        {/* Action Menu */}
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleCloseMenu}
        >
          <MenuItem onClick={() => openEditDialog(menuUser!)}>
            <ListItemIcon>
              <Edit fontSize="small" />
            </ListItemIcon>
            <ListItemText>Edit User</ListItemText>
          </MenuItem>
          <MenuItem onClick={() => openResetPasswordDialog(menuUser!)}>
            <ListItemIcon>
              <Lock fontSize="small" />
            </ListItemIcon>
            <ListItemText>Reset Password</ListItemText>
          </MenuItem>
          <MenuItem
            onClick={() => openDeleteDialog(menuUser!)}
            disabled={menuUser?.id === currentUser?.id}
          >
            <ListItemIcon>
              <Delete fontSize="small" />
            </ListItemIcon>
            <ListItemText>Delete User</ListItemText>
          </MenuItem>
        </Menu>

        {/* Create User Dialog */}
        <Dialog open={newUserDialogOpen} onClose={() => setNewUserDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Add New User</DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 1 }}>
              <TextField
                fullWidth
                label="Username"
                value={newUserForm.username}
                onChange={(e) => setNewUserForm({ ...newUserForm, username: e.target.value })}
                margin="normal"
                required
              />
              <TextField
                fullWidth
                label="Email"
                type="email"
                value={newUserForm.email}
                onChange={(e) => setNewUserForm({ ...newUserForm, email: e.target.value })}
                margin="normal"
                required
              />
              <TextField
                fullWidth
                label="Full Name"
                value={newUserForm.full_name}
                onChange={(e) => setNewUserForm({ ...newUserForm, full_name: e.target.value })}
                margin="normal"
              />
              <TextField
                fullWidth
                label="Password"
                type="password"
                value={newUserForm.password}
                onChange={(e) => setNewUserForm({ ...newUserForm, password: e.target.value })}
                margin="normal"
                required
                helperText="Password must be at least 8 characters"
              />
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setNewUserDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleCreateUser}
              variant="contained"
              disabled={saving}
              startIcon={saving ? <CircularProgress size={16} /> : <Add />}
            >
              {saving ? 'Creating...' : 'Create User'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Edit User Dialog */}
        <Dialog open={editUserDialogOpen} onClose={() => setEditUserDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Edit User: {selectedUser?.username}</DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 1 }}>
              <TextField
                fullWidth
                label="Email"
                type="email"
                value={editUserForm.email}
                onChange={(e) => setEditUserForm({ ...editUserForm, email: e.target.value })}
                margin="normal"
                required
              />
              <TextField
                fullWidth
                label="Full Name"
                value={editUserForm.full_name}
                onChange={(e) => setEditUserForm({ ...editUserForm, full_name: e.target.value })}
                margin="normal"
              />
              <FormControl fullWidth margin="normal">
                <InputLabel>Role</InputLabel>
                <Select
                  value={editUserForm.role}
                  label="Role"
                  onChange={(e) => setEditUserForm({ ...editUserForm, role: e.target.value })}
                  disabled={selectedUser?.id === currentUser?.id}
                >
                  <MenuItem value="admin">Admin</MenuItem>
                  <MenuItem value="analyst">Analyst</MenuItem>
                  <MenuItem value="auditor">Auditor</MenuItem>
                  <MenuItem value="viewer">Viewer</MenuItem>
                </Select>
              </FormControl>
              <FormControlLabel
                control={
                  <Switch
                    checked={editUserForm.is_active}
                    onChange={(e) => setEditUserForm({ ...editUserForm, is_active: e.target.checked })}
                    disabled={selectedUser?.id === currentUser?.id}
                  />
                }
                label="Active"
              />
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setEditUserDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleUpdateUser}
              variant="contained"
              disabled={saving}
              startIcon={saving ? <CircularProgress size={16} /> : <Edit />}
            >
              {saving ? 'Updating...' : 'Update User'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Reset Password Dialog */}
        <Dialog open={resetPasswordDialogOpen} onClose={() => setResetPasswordDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Reset Password: {selectedUser?.username}</DialogTitle>
          <DialogContent>
            <TextField
              fullWidth
              label="New Password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              margin="normal"
              required
              helperText="Password must be at least 8 characters"
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setResetPasswordDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleResetPassword}
              variant="contained"
              color="warning"
              disabled={saving}
              startIcon={saving ? <CircularProgress size={16} /> : <Lock />}
            >
              {saving ? 'Resetting...' : 'Reset Password'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Delete User Dialog */}
        <Dialog open={deleteUserDialogOpen} onClose={() => setDeleteUserDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Delete User: {selectedUser?.username}</DialogTitle>
          <DialogContent>
            <Alert severity="warning" sx={{ mb: 2 }}>
              This action cannot be undone. The user will permanently lose access to the system.
            </Alert>
            <Typography>
              Are you sure you want to delete user <strong>{selectedUser?.username}</strong>?
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteUserDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleDeleteUser}
              variant="contained"
              color="error"
              disabled={saving}
              startIcon={saving ? <CircularProgress size={16} /> : <Delete />}
            >
              {saving ? 'Deleting...' : 'Delete User'}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
};

export default SystemSettings;