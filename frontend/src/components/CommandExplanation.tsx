import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  Divider,
  Grid,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Tooltip,
  CircularProgress,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Terminal as TerminalIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { getScanCommandExplanation, CommandExplanation } from '../services/api';

interface CommandExplanationProps {
  scanId: number;
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel.toLowerCase()) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    default:
      return 'success';
  }
};

const getRiskIcon = (riskLevel: string) => {
  switch (riskLevel.toLowerCase()) {
    case 'high':
      return <ErrorIcon />;
    case 'medium':
      return <WarningIcon />;
    case 'low':
    default:
      return <InfoIcon />;
  }
};

const getCategoryColor = (category: string) => {
  switch (category.toLowerCase()) {
    case 'scan techniques':
      return 'primary';
    case 'service detection':
    case 'os detection':
      return 'secondary';
    case 'script scanning':
    case 'aggressive':
      return 'error';
    case 'timing':
    case 'performance':
      return 'warning';
    case 'stealth':
      return 'success';
    default:
      return 'default';
  }
};

const CommandExplanationComponent: React.FC<CommandExplanationProps> = ({ scanId }) => {
  const [explanation, setExplanation] = useState<CommandExplanation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  useEffect(() => {
    const loadCommandExplanation = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await getScanCommandExplanation(scanId);
        setExplanation(data);
      } catch (err) {
        console.error('Error loading command explanation:', err);
        setError('Failed to load command explanation');
      } finally {
        setLoading(false);
      }
    };

    loadCommandExplanation();
  }, [scanId]);

  const handleCategoryToggle = (category: string) => {
    const newExpanded = new Set(expandedCategories);
    if (newExpanded.has(category)) {
      newExpanded.delete(category);
    } else {
      newExpanded.add(category);
    }
    setExpandedCategories(newExpanded);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" py={4}>
        <CircularProgress size={40} />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ my: 2 }}>
        {error}
      </Alert>
    );
  }

  if (!explanation) {
    return null;
  }

  if (!explanation.has_command) {
    return (
      <Alert severity="info" sx={{ my: 2 }}>
        <Typography variant="body2">
          <strong>Tool:</strong> {explanation.tool}
        </Typography>
        <Typography variant="body2" sx={{ mt: 1 }}>
          {explanation.message}
        </Typography>
      </Alert>
    );
  }

  if (explanation.message && !explanation.arguments) {
    return (
      <Card sx={{ my: 2 }}>
        <CardContent>
          <Box display="flex" alignItems="center" mb={2}>
            <TerminalIcon sx={{ mr: 1 }} />
            <Typography variant="h6">Command Information</Typography>
          </Box>
          <Typography variant="body2" sx={{ mb: 1 }}>
            <strong>Tool:</strong> {explanation.tool}
          </Typography>
          <Paper sx={{ p: 2, bgcolor: 'action.hover', fontFamily: 'monospace', mb: 2 }}>
            <Typography variant="body2" style={{ wordBreak: 'break-all' }}>
              {explanation.command}
            </Typography>
          </Paper>
          <Alert severity="warning">
            {explanation.message}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  // Group arguments by category
  const argumentsByCategory: Record<string, typeof explanation.arguments> = {};
  if (explanation.arguments) {
    explanation.arguments.forEach(arg => {
      if (!argumentsByCategory[arg.category]) {
        argumentsByCategory[arg.category] = [];
      }
      argumentsByCategory[arg.category]!.push(arg);
    });
  }

  return (
    <Card sx={{ my: 2 }}>
      <CardContent>
        <Box display="flex" alignItems="center" mb={2}>
          <TerminalIcon sx={{ mr: 1 }} />
          <Typography variant="h6">Command Analysis</Typography>
        </Box>

        {/* Basic Command Info */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6}>
            <Typography variant="body2" color="text.secondary">
              <strong>Tool:</strong> {explanation.tool}
            </Typography>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Typography variant="body2" color="text.secondary">
              <strong>Scan Type:</strong> {explanation.scan_type}
            </Typography>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="body2" color="text.secondary">
              <strong>Target:</strong> {explanation.target}
            </Typography>
          </Grid>
        </Grid>

        {/* Command String */}
        <Box mb={3}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Command Line:
          </Typography>
          <Paper sx={{ p: 2, bgcolor: 'action.hover' }}>
            <Typography 
              variant="body2" 
              component="code" 
              style={{ 
                fontFamily: 'monospace',
                fontSize: '0.85rem',
                wordBreak: 'break-all',
                whiteSpace: 'pre-wrap'
              }}
            >
              {explanation.command}
            </Typography>
          </Paper>
        </Box>

        {/* Summary and Risk Assessment */}
        <Box mb={3}>
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>Summary:</strong> {explanation.summary}
            </Typography>
          </Alert>
          
          <Alert severity={explanation.risk_assessment?.includes('High') ? 'error' : 
                            explanation.risk_assessment?.includes('Medium') ? 'warning' : 'success'}>
            <Typography variant="body2">
              <strong>Risk Assessment:</strong> {explanation.risk_assessment}
            </Typography>
          </Alert>
        </Box>

        <Divider sx={{ my: 2 }} />

        {/* Arguments by Category */}
        <Typography variant="h6" sx={{ mb: 2 }}>
          <CodeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Command Arguments
        </Typography>

        {Object.entries(argumentsByCategory).map(([category, args]) => (
          <Accordion
            key={category}
            expanded={expandedCategories.has(category)}
            onChange={() => handleCategoryToggle(category)}
            sx={{ mb: 1 }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" width="100%">
                <SecurityIcon sx={{ mr: 1 }} />
                <Typography variant="subtitle1" sx={{ flexGrow: 1 }}>
                  {category}
                </Typography>
                <Chip
                  label={`${args?.length || 0} argument${args?.length !== 1 ? 's' : ''}`}
                  size="small"
                  color={getCategoryColor(category)}
                  sx={{ mr: 2 }}
                />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                {args?.map((arg, index) => (
                  <ListItem key={index} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 40 }}>
                      <Tooltip title={`Risk Level: ${arg.risk_level}`}>
                        <Chip
                          icon={getRiskIcon(arg.risk_level)}
                          label=""
                          size="small"
                          color={getRiskColor(arg.risk_level)}
                          sx={{ minWidth: 24, '& .MuiChip-label': { px: 0 } }}
                        />
                      </Tooltip>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography 
                          variant="body2" 
                          component="code"
                          sx={{ 
                            fontFamily: 'monospace',
                            bgcolor: 'action.hover',
                            px: 1,
                            py: 0.5,
                            borderRadius: 1,
                            fontSize: '0.8rem'
                          }}
                        >
                          {arg.arg}
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" sx={{ mt: 1 }}>
                            {arg.description}
                          </Typography>
                          {arg.examples && arg.examples.length > 0 && (
                            <Box sx={{ mt: 1 }}>
                              <Typography variant="caption" color="text.secondary">
                                Examples: {arg.examples.join(', ')}
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        ))}
      </CardContent>
    </Card>
  );
};

export default CommandExplanationComponent;