import React from 'react';
import { Box, Typography, useTheme } from '@mui/material';

const VersionFooter: React.FC = () => {
  const theme = useTheme();
  
  // Get build timestamp from environment or use current build time
  const buildTime = process.env.REACT_APP_BUILD_TIME || new Date().toISOString();
  const version = process.env.REACT_APP_VERSION || '1.0.0';
  const gitCommit = process.env.REACT_APP_GIT_COMMIT || 'dev';
  
  return (
    <Box
      sx={{
        position: 'fixed',
        bottom: 0,
        right: 0,
        padding: 1,
        backgroundColor: theme.palette.mode === 'dark' 
          ? 'rgba(0, 0, 0, 0.7)' 
          : 'rgba(255, 255, 255, 0.7)',
        borderTopLeftRadius: 1,
        backdropFilter: 'blur(4px)',
        zIndex: 1000,
      }}
    >
      <Typography 
        variant="caption" 
        sx={{ 
          fontSize: '0.7rem',
          color: theme.palette.text.secondary,
          fontFamily: 'monospace',
        }}
      >
        NetworkMapper v{version} | Built: {new Date(buildTime).toLocaleString()} | {gitCommit.substring(0, 7)}
      </Typography>
    </Box>
  );
};

export default VersionFooter;