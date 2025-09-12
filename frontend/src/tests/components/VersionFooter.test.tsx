import React from 'react';
import { render, screen } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import VersionFooter from '../../components/VersionFooter';

// Mock environment variables
const mockEnv = {
  REACT_APP_VERSION: '1.4.1',
  REACT_APP_BUILD_TIME: '2024-01-01T12:00:00.000Z',
  REACT_APP_GIT_COMMIT: 'abc123def456',
};

// Helper function to render component with theme
const renderWithTheme = (component: React.ReactElement, darkMode = false) => {
  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
    },
  });
  
  return render(
    <ThemeProvider theme={theme}>
      {component}
    </ThemeProvider>
  );
};

describe('VersionFooter', () => {
  // Store original env
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset environment variables
    process.env = { ...originalEnv, ...mockEnv };
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
  });

  it('renders version information correctly', () => {
    renderWithTheme(<VersionFooter />);
    
    // Check that version is displayed
    expect(screen.getByText(/NetworkMapper v1\.5\.0/)).toBeInTheDocument();
    
    // Check that build time is displayed
    expect(screen.getByText(/Built:/)).toBeInTheDocument();
    
    // Check that git commit hash is displayed (first 7 characters)
    expect(screen.getByText(/abc123d/)).toBeInTheDocument();
  });

  it('renders with light theme styles', () => {
    renderWithTheme(<VersionFooter />, false);
    
    const footer = screen.getByText(/NetworkMapper v1\.5\.0/).closest('div');
    expect(footer).toBeInTheDocument();
  });

  it('renders with dark theme styles', () => {
    renderWithTheme(<VersionFooter />, true);
    
    const footer = screen.getByText(/NetworkMapper v1\.5\.0/).closest('div');
    expect(footer).toBeInTheDocument();
  });

  it('handles missing environment variables gracefully', () => {
    // Clear environment variables
    delete process.env.REACT_APP_VERSION;
    delete process.env.REACT_APP_BUILD_TIME;
    delete process.env.REACT_APP_GIT_COMMIT;

    renderWithTheme(<VersionFooter />);
    
    // Should show default values
    expect(screen.getByText(/NetworkMapper v1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByText(/Built:/)).toBeInTheDocument();
    expect(screen.getByText(/dev/)).toBeInTheDocument();
  });

  it('truncates git commit hash to 7 characters', () => {
    process.env.REACT_APP_GIT_COMMIT = 'abcdefghijklmnop';
    
    renderWithTheme(<VersionFooter />);
    
    // Should only show first 7 characters
    expect(screen.getByText(/abcdefg/)).toBeInTheDocument();
    expect(screen.queryByText(/abcdefghijklmnop/)).not.toBeInTheDocument();
  });

  it('formats build time correctly', () => {
    renderWithTheme(<VersionFooter />);
    
    // Should display formatted date
    const buildTimeElement = screen.getByText(/Built:/);
    expect(buildTimeElement).toBeInTheDocument();
    
    // The exact format depends on locale, but should contain date info
    expect(buildTimeElement.textContent).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);
  });
});