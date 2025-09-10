import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import Dashboard from '../../pages/Dashboard';

// Mock the API module
jest.mock('../../services/api', () => ({
  getDashboardStats: jest.fn(),
  getPortStats: jest.fn(),
  getOsStats: jest.fn(),
}));

import * as api from '../../services/api';
const mockedApi = api as jest.Mocked<typeof api>;

// Mock Chart.js components
jest.mock('react-chartjs-2', () => ({
  Bar: ({ data }: any) => <div data-testid="bar-chart">{JSON.stringify(data)}</div>,
  Doughnut: ({ data }: any) => <div data-testid="doughnut-chart">{JSON.stringify(data)}</div>,
}));

// Mock the RiskAssessmentWidget component
jest.mock('../../components/RiskAssessmentWidget', () => {
  return function MockRiskAssessmentWidget() {
    return <div data-testid="risk-assessment-widget">Risk Assessment Widget</div>;
  };
});

const mockDashboardStats = {
  total_scans: 5,
  total_hosts: 150,
  total_ports: 1200,
  up_hosts: 120,
  open_ports: 450,
  total_subnets: 3,
  recent_scans: [
    {
      id: 1,
      filename: 'test_scan.gnmap',
      scan_type: 'nmap_gnmap',
      created_at: '2024-01-01T12:00:00Z',
      total_hosts: 50,
      up_hosts: 40,
      total_ports: 500,
      open_ports: 200,
    },
  ],
  subnet_stats: [
    {
      id: 1,
      cidr: '192.168.1.0/24',
      scope_name: 'Test Scope',
      description: 'Test subnet',
      host_count: 50,
      total_addresses: 254,
      usable_addresses: 252,
      utilization_percentage: 19.8,
      risk_level: 'medium',
      network_address: '192.168.1.0',
      is_private: true,
    },
  ],
};

const mockPortStats = [
  { port: 80, service: 'http', count: 25 },
  { port: 443, service: 'https', count: 20 },
  { port: 22, service: 'ssh', count: 30 },
];

const mockOsStats = [
  { os: 'Linux', count: 60 },
  { os: 'Windows', count: 40 },
  { os: 'Unknown', count: 20 },
];

// Helper function to render component with theme
const renderWithTheme = (component: React.ReactElement) => {
  const theme = createTheme();
  
  return render(
    <ThemeProvider theme={theme}>
      {component}
    </ThemeProvider>
  );
};

describe('Dashboard', () => {
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Setup default API responses
    mockedApi.getDashboardStats.mockResolvedValue(mockDashboardStats);
    mockedApi.getPortStats.mockResolvedValue(mockPortStats);
    mockedApi.getOsStats.mockResolvedValue(mockOsStats);
  });

  it('renders dashboard title', async () => {
    renderWithTheme(<Dashboard />);
    
    expect(screen.getByText('Network Mapper Dashboard')).toBeInTheDocument();
  });

  it('displays loading state initially', () => {
    renderWithTheme(<Dashboard />);
    
    // Should show loading indicators
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('displays dashboard statistics after loading', async () => {
    renderWithTheme(<Dashboard />);
    
    // Wait for API calls to complete
    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument(); // total_scans
      expect(screen.getByText('150')).toBeInTheDocument(); // total_hosts
      expect(screen.getByText('120')).toBeInTheDocument(); // up_hosts
      expect(screen.getByText('1200')).toBeInTheDocument(); // total_ports
      expect(screen.getByText('450')).toBeInTheDocument(); // open_ports
    });
  });

  it('renders charts after data loads', async () => {
    renderWithTheme(<Dashboard />);
    
    await waitFor(() => {
      expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
      expect(screen.getByTestId('doughnut-chart')).toBeInTheDocument();
    });
  });

  it('displays recent scans table', async () => {
    renderWithTheme(<Dashboard />);
    
    await waitFor(() => {
      expect(screen.getByText('Recent Scans')).toBeInTheDocument();
      expect(screen.getByText('test_scan.gnmap')).toBeInTheDocument();
      expect(screen.getByText('nmap_gnmap')).toBeInTheDocument();
    });
  });

  it('renders risk assessment widget', async () => {
    renderWithTheme(<Dashboard />);
    
    await waitFor(() => {
      expect(screen.getByTestId('risk-assessment-widget')).toBeInTheDocument();
    });
  });

  it('handles API errors gracefully', async () => {
    // Mock API to throw error
    mockedApi.getDashboardStats.mockRejectedValue(new Error('API Error'));
    mockedApi.getPortStats.mockRejectedValue(new Error('API Error'));
    mockedApi.getOsStats.mockRejectedValue(new Error('API Error'));
    
    renderWithTheme(<Dashboard />);
    
    // Should still render basic structure without crashing
    expect(screen.getByText('Network Mapper Dashboard')).toBeInTheDocument();
    
    // Should show loading indicators or empty states
    await waitFor(() => {
      expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    });
  });

  it('calls API endpoints on mount', () => {
    renderWithTheme(<Dashboard />);
    
    expect(mockedApi.getDashboardStats).toHaveBeenCalledTimes(1);
    expect(mockedApi.getPortStats).toHaveBeenCalledTimes(1);
    expect(mockedApi.getOsStats).toHaveBeenCalledTimes(1);
  });
});