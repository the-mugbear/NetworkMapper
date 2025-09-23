import React, { ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  AppBar,
  Box,
  CssBaseline,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  Tooltip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Computer as HostsIcon,
  Assessment as ScansIcon,
  NetworkCheck as ScopesIcon,
  Error as ErrorIcon,
  Security as SecurityIcon,
  Key as KeyIcon,
  Brightness4 as DarkModeIcon,
  Brightness7 as LightModeIcon,
} from '@mui/icons-material';
import { useTheme as useCustomTheme } from '../contexts/ThemeContext';
import { useAuth } from '../contexts/AuthContext';
import UserMenu from './UserMenu';

const drawerWidth = 240;

interface LayoutProps {
  children: ReactNode;
}

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard', requiredRole: 'viewer' },
  { text: 'Scans', icon: <ScansIcon />, path: '/scans', requiredRole: 'viewer' },
  { text: 'Hosts', icon: <HostsIcon />, path: '/hosts', requiredRole: 'viewer' },
  { text: 'Scopes', icon: <ScopesIcon />, path: '/scopes', requiredRole: 'analyst' },
  { text: 'Risk Assessment', icon: <SecurityIcon />, path: '/risk-assessment', requiredRole: 'viewer' },
  { text: 'Default Credentials', icon: <KeyIcon />, path: '/default-credentials', requiredRole: 'viewer' },
  { text: 'Parse Errors', icon: <ErrorIcon />, path: '/parse-errors', requiredRole: 'analyst' },
];

export default function Layout({ children }: LayoutProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const { isDarkMode, toggleTheme } = useCustomTheme();
  const { hasPermission } = useAuth();

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleNavigation = (path: string) => {
    navigate(path);
  };

  const drawer = (
    <div>
      <Toolbar>
        <Typography variant="h6" noWrap component="div">
          NetworkMapper
        </Typography>
      </Toolbar>
      <List>
        {menuItems
          .filter((item) => hasPermission(item.requiredRole))
          .map((item) => (
            <ListItem key={item.text} disablePadding>
              <ListItemButton
                selected={location.pathname === item.path}
                onClick={() => handleNavigation(item.path)}
              >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.text} />
              </ListItemButton>
            </ListItem>
          ))}
      </List>
    </div>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            NetworkMapper Security Platform
          </Typography>
          <Tooltip title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}>
            <IconButton
              color="inherit"
              onClick={toggleTheme}
              aria-label={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {isDarkMode ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
          <UserMenu />
        </Toolbar>
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
        aria-label="mailbox folders"
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>
      <Box
        component="main"
        sx={{ flexGrow: 1, p: 3, width: { sm: `calc(100% - ${drawerWidth}px)` } }}
      >
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
}