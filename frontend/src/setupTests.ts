// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock axios for API calls
vi.mock('axios');

// Mock Chart.js for charts
vi.mock('chart.js', () => ({
  Chart: {
    register: vi.fn(),
  },
  CategoryScale: vi.fn(),
  LinearScale: vi.fn(),
  BarElement: vi.fn(),
  Title: vi.fn(),
  Tooltip: vi.fn(),
  Legend: vi.fn(),
}));

// Mock react-chartjs-2
vi.mock('react-chartjs-2', () => ({
  Bar: () => 'Bar Chart Mock',
  Doughnut: () => 'Doughnut Chart Mock',
}));

// Mock react-router-dom for navigation
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => vi.fn(),
    useParams: () => ({ id: '1' }),
    useLocation: () => ({
      pathname: '/',
      search: '',
      hash: '',
      state: null,
    }),
  };
});

// Mock file download - this will be handled by jsdom
global.URL = global.URL || {
  createObjectURL: vi.fn(() => 'mock-url'),
  revokeObjectURL: vi.fn(),
};