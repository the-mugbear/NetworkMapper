import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Box } from '@mui/material';
import { CustomThemeProvider } from './contexts/ThemeContext';
import { AuthProvider } from './contexts/AuthContext';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import VersionFooter from './components/VersionFooter';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Hosts from './pages/Hosts';
import HostDetail from './pages/HostDetail';
import Scopes from './pages/Scopes';
import ScopeDetail from './pages/ScopeDetail';
import ParseErrors from './pages/ParseErrors';
import RiskAssessment from './pages/RiskAssessment';
import DefaultCredentials from './pages/DefaultCredentials';
import Profile from './pages/Profile';
import SystemSettings from './pages/SystemSettings';

function App() {
  return (
    <CustomThemeProvider>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />

          {/* Protected routes */}
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <Box sx={{ display: 'flex' }}>
                  <Layout>
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/upload" element={<Navigate to="/scans" replace />} />
                      <Route
                        path="/scans"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <Scans />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/scans/:scanId"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <ScanDetail />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/hosts"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <Hosts />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/hosts/:hostId"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <HostDetail />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/scopes"
                        element={
                          <ProtectedRoute requiredRole="analyst">
                            <Scopes />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/scopes/:scopeId"
                        element={
                          <ProtectedRoute requiredRole="analyst">
                            <ScopeDetail />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/parse-errors"
                        element={
                          <ProtectedRoute requiredRole="analyst">
                            <ParseErrors />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/risk-assessment"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <RiskAssessment />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/default-credentials"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <DefaultCredentials />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/profile"
                        element={
                          <ProtectedRoute requiredRole="viewer">
                            <Profile />
                          </ProtectedRoute>
                        }
                      />
                      <Route
                        path="/system-settings"
                        element={
                          <ProtectedRoute requiredRole="admin">
                            <SystemSettings />
                          </ProtectedRoute>
                        }
                      />
                    </Routes>
                  </Layout>
                  <VersionFooter />
                </Box>
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </CustomThemeProvider>
  );
}

export default App;