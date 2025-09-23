// Dynamic API URL resolution for network access
export const getApiBaseUrl = () => {
  // If REACT_APP_API_URL is set, use it
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }

  // Otherwise, derive from current window location for network compatibility
  const currentHost = window.location.hostname;
  const currentPort = window.location.port;

  if (currentHost === 'localhost' || currentHost === '127.0.0.1') {
    // For localhost, determine backend port based on frontend port
    if (currentPort === '3001') {
      // Dev instance: frontend on 3001, backend on 8001
      return 'http://localhost:8001';
    } else {
      // Production instance: frontend on 3000, backend on 8000
      return 'http://localhost:8000';
    }
  } else {
    // For network deployments, backend is always on port 8000
    return `http://${currentHost}:8000`;
  }
};