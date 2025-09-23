import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { flushSync } from 'react-dom';
import { logger, createAuthLogger } from '../utils/logger';

interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
  hasRole: (role: string) => boolean;
  hasPermission: (requiredRole: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

const ROLE_HIERARCHY = {
  admin: 4,
  analyst: 3,
  auditor: 2,
  viewer: 1
};

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  const authLogger = createAuthLogger();

  // Log initial state
  authLogger.debug('AuthProvider initialized', {
    pathname: location.pathname,
    search: location.search,
    state: location.state
  });

  useEffect(() => {
    const timer = authLogger.timer('Initial auth check');
    authLogger.debug('Starting initial authentication check');

    // Check for existing token on mount
    const storedToken = localStorage.getItem('auth_token');
    const storedUser = localStorage.getItem('auth_user');

    authLogger.debug('Retrieved stored auth data', {
      hasToken: !!storedToken,
      hasUser: !!storedUser,
      tokenLength: storedToken?.length,
      userDataLength: storedUser?.length
    });

    if (storedToken && storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        authLogger.debug('Parsed stored user data', {
          userId: userData.id,
          username: userData.username,
          role: userData.role
        });

        authLogger.debug('Setting token and user from storage');
        setToken(storedToken);
        setUser(userData);

        authLogger.info('Authentication restored from storage', {
          userId: userData.id,
          username: userData.username
        });

        // TODO: Verify token is still valid - temporarily disabled to test redirect issue
        // verifyToken(storedToken);
      } catch (error) {
        authLogger.error('Error parsing stored user data', { error: error.message });
        clearAuthData();
      }
    } else {
      authLogger.debug('No stored authentication data found');
    }

    authLogger.debug('Setting loading to false');
    setIsLoading(false);
    timer();
  }, []);

  const verifyToken = async (authToken: string) => {
    const timer = authLogger.timer('Token verification');
    authLogger.debug('Starting token verification', {
      tokenLength: authToken?.length,
      hasToken: !!authToken
    });

    try {
      const response = await fetch('/api/v1/auth/profile', {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
      });

      authLogger.debug('Token verification response received', {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok
      });

      if (!response.ok) {
        if (response.status === 401) {
          authLogger.warn('Token verification failed - unauthorized', {
            status: response.status,
            action: 'clearing_auth_data_and_redirecting'
          });
          clearAuthData();
          navigate('/login');
        } else {
          authLogger.warn('Token verification failed - other error', {
            status: response.status,
            statusText: response.statusText
          });
        }
        timer();
        return;
      }

      const userData = await response.json();
      authLogger.info('Token verification successful', {
        userId: userData.id,
        username: userData.username
      });
      setUser(userData);
      timer();
    } catch (error) {
      authLogger.error('Token verification failed with exception', {
        error: error.message,
        action: 'clearing_auth_data'
      });
      clearAuthData();
      timer();
    }
  };

  const login = async (username: string, password: string) => {
    const timer = authLogger.timer('Login process');
    authLogger.info('Login attempt started', {
      username,
      currentPath: location.pathname,
      fromPath: location.state?.from?.pathname
    });
    authLogger.audit('LOGIN_ATTEMPT', { username });

    try {
      authLogger.debug('Sending login request to API');
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      authLogger.debug('Login API response received', {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        headers: Object.fromEntries(response.headers.entries())
      });

      if (!response.ok) {
        const errorData = await response.json();
        authLogger.error('Login API failed', {
          status: response.status,
          statusText: response.statusText,
          errorData
        });
        authLogger.audit('LOGIN_FAILED', { username, reason: errorData.detail });
        throw new Error(errorData.detail || 'Login failed');
      }

      const data = await response.json();
      authLogger.debug('Login response data received', {
        hasAccessToken: !!data.access_token,
        tokenType: data.token_type,
        expiresIn: data.expires_in,
        hasUser: !!data.user,
        userId: data.user?.id,
        userRole: data.user?.role
      });

      // Store in localStorage first
      authLogger.debug('Storing auth data in localStorage');
      localStorage.setItem('auth_token', data.access_token);
      localStorage.setItem('auth_user', JSON.stringify(data.user));

      authLogger.debug('Setting token and user state synchronously');
      // Use flushSync to ensure state updates are synchronous
      flushSync(() => {
        setToken(data.access_token);
        setUser(data.user);
      });

      authLogger.info('Login successful', {
        userId: data.user.id,
        username: data.user.username,
        role: data.user.role,
        tokenSet: !!data.access_token,
        userSet: !!data.user
      });
      authLogger.audit('LOGIN_SUCCESS', {
        userId: data.user.id,
        username: data.user.username,
        role: data.user.role
      });

      // Send audit log to backend (asynchronously, don't block login)
      logAuditEvent('login_success', 'authentication', {
        userId: data.user.id,
        username: data.user.username,
        role: data.user.role
      }).catch(error => {
        authLogger.warn('Backend audit logging failed for login', { error: error.message });
      });

      // Navigate immediately after synchronous state update
      const from = location.state?.from?.pathname || '/';
      authLogger.debug('Navigating after successful login', {
        fromPath: from,
        currentPath: location.pathname,
        replace: true,
        authState: { hasToken: !!data.access_token, hasUser: !!data.user }
      });

      navigate(from, { replace: true });
      timer();

    } catch (error) {
      authLogger.error('Login process failed', {
        error: error.message,
        username
      });
      timer();
      throw error;
    }
  };

  const logout = async () => {
    const timer = authLogger.timer('Logout process');
    authLogger.info('Logout initiated', {
      hasToken: !!token,
      userId: user?.id,
      username: user?.username
    });
    authLogger.audit('LOGOUT_INITIATED', {
      userId: user?.id,
      username: user?.username
    });

    try {
      if (token) {
        authLogger.debug('Calling logout endpoint');
        // Call logout endpoint to revoke session
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
        authLogger.debug('Logout endpoint called successfully');
      } else {
        authLogger.debug('No token available for logout endpoint call');
      }
    } catch (error) {
      authLogger.error('Logout endpoint call failed', { error: error.message });
    } finally {
      authLogger.debug('Clearing auth data and navigating to login');
      clearAuthData();
      navigate('/login');
      timer();
    }
  };

  const clearAuthData = () => {
    authLogger.debug('Clearing authentication data', {
      hadUser: !!user,
      hadToken: !!token,
      userId: user?.id,
      username: user?.username
    });

    setUser(null);
    setToken(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_user');

    authLogger.info('Authentication data cleared');
    authLogger.audit('AUTH_DATA_CLEARED', {
      previousUserId: user?.id,
      previousUsername: user?.username
    });
  };

  const hasRole = (role: string): boolean => {
    return user?.role === role;
  };

  const hasPermission = (requiredRole: string): boolean => {
    if (!user) return false;

    const userLevel = ROLE_HIERARCHY[user.role as keyof typeof ROLE_HIERARCHY] || 0;
    const requiredLevel = ROLE_HIERARCHY[requiredRole as keyof typeof ROLE_HIERARCHY] || 0;

    return userLevel >= requiredLevel;
  };

  const logAuditEvent = async (action: string, resourceType: string, details?: any) => {
    if (!token) {
      authLogger.debug('Audit logging skipped - no token available', { action, resourceType });
      return;
    }

    try {
      authLogger.debug('Sending audit log to backend', { action, resourceType, details });
      const response = await fetch('/api/v1/audit/log', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action,
          resource_type: resourceType,
          details: details || { timestamp: new Date().toISOString() }
        }),
      });

      if (!response.ok) {
        authLogger.warn('Audit logging failed', {
          action,
          resourceType,
          status: response.status,
          statusText: response.statusText
        });
      } else {
        authLogger.debug('Audit log sent successfully', { action, resourceType });
      }
    } catch (error) {
      authLogger.error('Audit logging failed with exception', {
        action,
        resourceType,
        error: error.message
      });
    }
  };

  // Track authentication state changes
  const isAuthenticated = !!user && !!token;

  // Log whenever authentication state changes
  useEffect(() => {
    authLogger.debug('Authentication state changed', {
      isAuthenticated,
      hasUser: !!user,
      hasToken: !!token,
      isLoading,
      userId: user?.id,
      username: user?.username,
      role: user?.role
    });

    if (isAuthenticated && !isLoading) {
      authLogger.info('User is authenticated', {
        userId: user?.id,
        username: user?.username,
        role: user?.role
      });
    } else if (!isAuthenticated && !isLoading) {
      authLogger.info('User is not authenticated');
    }
  }, [isAuthenticated, isLoading, user, token]);

  const value = {
    user,
    token,
    login,
    logout,
    isAuthenticated,
    isLoading,
    hasRole,
    hasPermission,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};