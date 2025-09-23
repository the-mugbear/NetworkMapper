import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  InputAdornment,
  IconButton,
  CircularProgress,
  Container,
  Divider,
  Chip
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Security as SecurityIcon,
  AccountCircle,
  Lock
} from '@mui/icons-material';

const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await login(username, password);
    } catch (err: any) {
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTogglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  return (
    <Container maxWidth="sm">
      <Box
        display="flex"
        flexDirection="column"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
        py={4}
      >
        <Card
          sx={{
            width: '100%',
            maxWidth: 450,
            boxShadow: 3,
            borderRadius: 2
          }}
        >
          <CardContent sx={{ p: 4 }}>
            {/* Header */}
            <Box textAlign="center" mb={4}>
              <SecurityIcon
                sx={{
                  fontSize: 64,
                  color: 'primary.main',
                  mb: 2
                }}
              />
              <Typography variant="h4" gutterBottom fontWeight="bold">
                NetworkMapper
              </Typography>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                A Modest Platform
              </Typography>
              <Divider sx={{ my: 2 }}>
                <Chip
                  label="Secure Access Required"
                  size="small"
                  color="primary"
                  variant="outlined"
                />
              </Divider>
            </Box>

            {/* Error Alert */}
            {error && (
              <Alert
                severity="error"
                sx={{ mb: 3 }}
                onClose={() => setError('')}
              >
                {error}
              </Alert>
            )}

            {/* Login Form */}
            <Box component="form" onSubmit={handleSubmit}>
              <TextField
                fullWidth
                label="Username"
                variant="outlined"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                disabled={isLoading}
                sx={{ mb: 3 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <AccountCircle color="action" />
                    </InputAdornment>
                  ),
                }}
                autoComplete="username"
                autoFocus
              />

              <TextField
                fullWidth
                label="Password"
                type={showPassword ? 'text' : 'password'}
                variant="outlined"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={isLoading}
                sx={{ mb: 4 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Lock color="action" />
                    </InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={handleTogglePasswordVisibility}
                        edge="end"
                        disabled={isLoading}
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                autoComplete="current-password"
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={isLoading || !username || !password}
                sx={{
                  py: 1.5,
                  fontSize: '1.1rem',
                  fontWeight: 'bold'
                }}
              >
                {isLoading ? (
                  <Box display="flex" alignItems="center" gap={1}>
                    <CircularProgress size={20} color="inherit" />
                    Authenticating...
                  </Box>
                ) : (
                  'Sign In'
                )}
              </Button>
            </Box>

            {/* Security Notice */}
            <Box mt={4} p={2} bgcolor="grey.50" borderRadius={1}>
              <Typography variant="body2" color="text.secondary" textAlign="center">
                <Lock sx={{ fontSize: 16, verticalAlign: 'middle', mr: 0.5 }} />
                This system contains sensitive security data.
                All access is logged and monitored.
              </Typography>
            </Box>
          </CardContent>
        </Card>

        {/* Footer */}
        <Box mt={3} textAlign="center">
          <Typography variant="body2" color="text.secondary">
            NetworkMapper 
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Unauthorized access is prohibited
          </Typography>
        </Box>
      </Box>
    </Container>
  );
};

export default Login;