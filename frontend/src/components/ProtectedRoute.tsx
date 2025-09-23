import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Box, CircularProgress, Typography } from '@mui/material';
import { logger } from '../utils/logger';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, requiredRole }) => {
  const { isAuthenticated, isLoading, hasPermission, user } = useAuth();
  const location = useLocation();

  // Log every render and decision
  useEffect(() => {
    logger.debug('PROTECTED_ROUTE', 'ProtectedRoute render', {
      pathname: location.pathname,
      requiredRole,
      isAuthenticated,
      isLoading,
      hasUser: !!user,
      userId: user?.id,
      username: user?.username,
      userRole: user?.role,
      hasPermission: requiredRole ? hasPermission(requiredRole) : true
    });
  });

  // Show loading spinner while checking authentication
  if (isLoading) {
    logger.debug('PROTECTED_ROUTE', 'Showing loading spinner', {
      pathname: location.pathname,
      requiredRole
    });
    return (
      <Box
        display="flex"
        flexDirection="column"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
        gap={2}
      >
        <CircularProgress size={40} />
        <Typography variant="body2" color="text.secondary">
          Verifying authentication...
        </Typography>
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    logger.warn('PROTECTED_ROUTE', 'Redirecting to login - not authenticated', {
      pathname: location.pathname,
      requiredRole,
      isAuthenticated,
      hasUser: !!user,
      userId: user?.id,
      username: user?.username,
      action: 'REDIRECT_TO_LOGIN'
    });
    logger.audit('PROTECTED_ROUTE', 'UNAUTHORIZED_ACCESS_ATTEMPT', {
      pathname: location.pathname,
      requiredRole,
      hasUser: !!user,
      userId: user?.id
    });
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check role-based permissions
  if (requiredRole && !hasPermission(requiredRole)) {
    logger.warn('PROTECTED_ROUTE', 'Access denied - insufficient permissions', {
      pathname: location.pathname,
      requiredRole,
      userRole: user?.role,
      userId: user?.id,
      username: user?.username,
      action: 'ACCESS_DENIED'
    });
    logger.audit('PROTECTED_ROUTE', 'INSUFFICIENT_PERMISSIONS', {
      pathname: location.pathname,
      requiredRole,
      userRole: user?.role,
      userId: user?.id,
      username: user?.username
    });
    return (
      <Box
        display="flex"
        flexDirection="column"
        justifyContent="center"
        alignItems="center"
        minHeight="50vh"
        gap={2}
        p={4}
      >
        <Typography variant="h5" color="error">
          Access Denied
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center">
          You don't have sufficient permissions to access this resource.
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Required role: <strong>{requiredRole}</strong>
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Your role: <strong>{user?.role}</strong>
        </Typography>
      </Box>
    );
  }

  logger.debug('PROTECTED_ROUTE', 'Access granted - rendering children', {
    pathname: location.pathname,
    requiredRole,
    userRole: user?.role,
    userId: user?.id,
    username: user?.username
  });

  return <>{children}</>;
};

export default ProtectedRoute;