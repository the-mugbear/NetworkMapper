import React, { useState } from 'react';
import {
  IconButton,
  Menu,
  MenuItem,
  Avatar,
  Typography,
  Divider,
  ListItemIcon,
  Box,
  Chip
} from '@mui/material';
import {
  AccountCircle,
  Logout,
  Settings,
  Security,
  Person,
  AdminPanelSettings,
  Visibility as ViewerIcon,
  Analytics as AnalystIcon,
  Assessment as AuditorIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const UserMenu: React.FC = () => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const { user, logout, hasPermission } = useAuth();
  const navigate = useNavigate();

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    handleClose();
    logout();
  };

  const handleProfileClick = () => {
    handleClose();
    navigate('/profile');
  };

  const handleSettingsClick = () => {
    handleClose();
    navigate('/system-settings');
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

  if (!user) return null;

  return (
    <>
      <IconButton onClick={handleClick} color="inherit">
        <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}>
          {user.username.charAt(0).toUpperCase()}
        </Avatar>
      </IconButton>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        PaperProps={{
          sx: {
            mt: 1,
            minWidth: 280,
            '& .MuiMenuItem-root': {
              px: 2,
              py: 1
            }
          }
        }}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        {/* User Info Header */}
        <Box px={2} py={1.5}>
          <Box display="flex" alignItems="center" gap={1} mb={1}>
            <Avatar sx={{ width: 40, height: 40, bgcolor: 'primary.main' }}>
              {user.username.charAt(0).toUpperCase()}
            </Avatar>
            <Box>
              <Typography variant="subtitle1" fontWeight="medium">
                {user.full_name || user.username}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {user.email}
              </Typography>
            </Box>
          </Box>

          <Box display="flex" alignItems="center" gap={1}>
            <Chip
              icon={getRoleIcon(user.role)}
              label={user.role.toUpperCase()}
              size="small"
              color={getRoleColor(user.role)}
              variant="outlined"
            />
            <Chip
              icon={<Security fontSize="small" />}
              label="Authenticated"
              size="small"
              color="success"
              variant="filled"
            />
          </Box>
        </Box>

        <Divider />

        {/* Profile Menu Item */}
        <MenuItem onClick={handleProfileClick}>
          <ListItemIcon>
            <AccountCircle fontSize="small" />
          </ListItemIcon>
          <Box>
            <Typography variant="body2">Profile</Typography>
            <Typography variant="caption" color="text.secondary">
              View and edit profile
            </Typography>
          </Box>
        </MenuItem>

        {/* Settings (Admin only) */}
        {hasPermission('admin') && (
          <MenuItem onClick={handleSettingsClick}>
            <ListItemIcon>
              <Settings fontSize="small" />
            </ListItemIcon>
            <Box>
              <Typography variant="body2">System Settings</Typography>
              <Typography variant="caption" color="text.secondary">
                Manage users and security
              </Typography>
            </Box>
          </MenuItem>
        )}

        <Divider />

        {/* Logout */}
        <MenuItem onClick={handleLogout}>
          <ListItemIcon>
            <Logout fontSize="small" color="error" />
          </ListItemIcon>
          <Box>
            <Typography variant="body2" color="error">
              Sign Out
            </Typography>
            <Typography variant="caption" color="text.secondary">
              End your session
            </Typography>
          </Box>
        </MenuItem>
      </Menu>
    </>
  );
};

export default UserMenu;