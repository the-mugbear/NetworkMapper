import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Box } from '@mui/material';
import { CustomThemeProvider } from './contexts/ThemeContext';
import Layout from './components/Layout';
import VersionFooter from './components/VersionFooter';
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Hosts from './pages/Hosts';
import HostDetail from './pages/HostDetail';
import Scopes from './pages/Scopes';
import ScopeDetail from './pages/ScopeDetail';
import ParseErrors from './pages/ParseErrors';
import RiskAssessment from './pages/RiskAssessment';

function App() {
  return (
    <CustomThemeProvider>
      <Box sx={{ display: 'flex' }}>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/upload" element={<Navigate to="/scans" replace />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:scanId" element={<ScanDetail />} />
            <Route path="/hosts" element={<Hosts />} />
            <Route path="/hosts/:hostId" element={<HostDetail />} />
            <Route path="/scopes" element={<Scopes />} />
            <Route path="/scopes/:scopeId" element={<ScopeDetail />} />
            <Route path="/parse-errors" element={<ParseErrors />} />
            <Route path="/risk-assessment" element={<RiskAssessment />} />
          </Routes>
        </Layout>
        <VersionFooter />
      </Box>
    </CustomThemeProvider>
  );
}

export default App;