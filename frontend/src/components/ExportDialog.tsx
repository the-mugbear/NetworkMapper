import React, { useState } from 'react';
import { getApiBaseUrl } from '../utils/apiUrl';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Box,
  Chip,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  LinearProgress,
  IconButton,
} from '@mui/material';
import {
  Close as CloseIcon,
  FileDownload as FileDownloadIcon,
  Description as HtmlIcon,
  TableChart as CsvIcon,
  Code as JsonIcon,
  PictureAsPdf as PdfIcon,
  Article as WordIcon,
  Assessment as ExcelIcon,
  Slideshow as PowerPointIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';

export interface ExportDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  exportType: 'scope' | 'scan' | 'out-of-scope';
  itemId?: number;
  itemName?: string;
}

interface ExportFormat {
  id: string;
  name: string;
  description: string;
  icon: React.ReactElement;
  available: boolean;
  recommended?: boolean;
  fileSize: string;
  features: string[];
}

const exportFormats: ExportFormat[] = [
  {
    id: 'html',
    name: 'Professional HTML Report',
    description: 'Interactive web-based report with professional styling and charts',
    icon: <HtmlIcon color="primary" />,
    available: true,
    recommended: true,
    fileSize: '~500KB',
    features: ['Professional styling', 'Interactive elements', 'Print-friendly', 'Charts & graphs']
  },
  {
    id: 'pdf',
    name: 'PDF Document',
    description: 'Professional PDF report suitable for sharing and presentations',
    icon: <PdfIcon color="error" />,
    available: false,
    fileSize: '~300KB',
    features: ['Professional layout', 'Executive summary', 'Charts included', 'Print-ready']
  },
  {
    id: 'csv',
    name: 'CSV Data Export',
    description: 'Raw data in comma-separated values format for analysis',
    icon: <CsvIcon color="success" />,
    available: true,
    fileSize: '~50KB',
    features: ['Raw data only', 'Excel compatible', 'Easy to analyze', 'Lightweight']
  },
  {
    id: 'json',
    name: 'JSON Data Export',
    description: 'Structured data in JSON format for API integration',
    icon: <JsonIcon color="info" />,
    available: true,
    fileSize: '~100KB',
    features: ['Complete data', 'API integration', 'Programmatic access', 'Structured format']
  },
  {
    id: 'excel',
    name: 'Excel Workbook',
    description: 'Multi-sheet Excel workbook with advanced formatting',
    icon: <ExcelIcon style={{ color: '#1d7044' }} />,
    available: false,
    fileSize: '~200KB',
    features: ['Multiple worksheets', 'Charts & graphs', 'Conditional formatting', 'Pivot tables']
  },
  {
    id: 'word',
    name: 'Word Document',
    description: 'Professional Word document report',
    icon: <WordIcon style={{ color: '#2b579a' }} />,
    available: false,
    fileSize: '~400KB',
    features: ['Professional layout', 'Executive summary', 'Easy editing', 'Corporate format']
  },
  {
    id: 'powerpoint',
    name: 'PowerPoint Presentation',
    description: 'Executive presentation slides with key findings',
    icon: <PowerPointIcon style={{ color: '#b7472a' }} />,
    available: false,
    fileSize: '~800KB',
    features: ['Executive slides', 'Key metrics', 'Visual charts', 'Presentation-ready']
  }
];

const ExportDialog: React.FC<ExportDialogProps> = ({
  open,
  onClose,
  title,
  exportType,
  itemId,
  itemName
}) => {
  const [selectedFormat, setSelectedFormat] = useState<string>('html');
  const [isExporting, setIsExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState(0);

  const selectedFormatData = exportFormats.find(f => f.id === selectedFormat);

  const handleExport = async () => {
    if (!selectedFormatData?.available) {
      return;
    }

    setIsExporting(true);
    setExportProgress(0);

    try {
      // Simulate progress updates
      const progressTimer = setInterval(() => {
        setExportProgress(prev => Math.min(prev + 10, 90));
      }, 200);

      // Build export URL based on type
      let exportUrl = '';
      if (exportType === 'scope' && itemId) {
        exportUrl = `/api/v1/export/scope/${itemId}?format_type=${selectedFormat}`;
      } else if (exportType === 'scan' && itemId) {
        exportUrl = `/api/v1/export/scan/${itemId}?format_type=${selectedFormat}`;
      } else if (exportType === 'out-of-scope') {
        exportUrl = `/api/v1/export/out-of-scope?format_type=${selectedFormat}`;
      }

      // Trigger download
      const link = document.createElement('a');
      link.href = `${getApiBaseUrl()}${exportUrl}`;
      link.download = `NetworkMapper_${exportType}_${itemName || 'report'}_${new Date().toISOString().split('T')[0]}.${selectedFormat}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      clearInterval(progressTimer);
      setExportProgress(100);

      // Close dialog after short delay
      setTimeout(() => {
        setIsExporting(false);
        setExportProgress(0);
        onClose();
      }, 1000);

    } catch (error) {
      console.error('Export failed:', error);
      setIsExporting(false);
      setExportProgress(0);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="h6">Export Report</Typography>
            <Typography variant="subtitle2" color="textSecondary">
              {title} {itemName && `- ${itemName}`}
            </Typography>
          </Box>
          <IconButton onClick={onClose}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        <Box mb={3}>
          <Typography variant="h6" gutterBottom>
            Select Export Format
          </Typography>
          <Typography variant="body2" color="textSecondary" paragraph>
            Choose the format that best suits your needs. HTML format is recommended for comprehensive reports.
          </Typography>
        </Box>

        <FormControl fullWidth variant="outlined" margin="normal">
          <InputLabel>Export Format</InputLabel>
          <Select
            value={selectedFormat}
            onChange={(e) => setSelectedFormat(e.target.value as string)}
            label="Export Format"
            disabled={isExporting}
          >
            {exportFormats.map((format) => (
              <MenuItem 
                key={format.id} 
                value={format.id}
                disabled={!format.available}
              >
                <Box display="flex" alignItems="center" width="100%">
                  <Box mr={2}>{format.icon}</Box>
                  <Box flex={1}>
                    <Typography variant="body1">
                      {format.name}
                      {format.recommended && (
                        <Chip 
                          label="Recommended" 
                          size="small" 
                          color="primary" 
                          style={{ marginLeft: 8 }}
                        />
                      )}
                      {!format.available && (
                        <Chip 
                          label="Coming Soon" 
                          size="small" 
                          color="default" 
                          variant="outlined"
                          style={{ marginLeft: 8 }}
                        />
                      )}
                    </Typography>
                  </Box>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {selectedFormatData && (
          <Box mt={3}>
            <Typography variant="h6" gutterBottom>
              Format Details
            </Typography>
            
            <Box display="flex" alignItems="center" mb={2}>
              <Box mr={2}>{selectedFormatData.icon}</Box>
              <Box>
                <Typography variant="subtitle1" fontWeight="medium">
                  {selectedFormatData.name}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Expected file size: {selectedFormatData.fileSize}
                </Typography>
              </Box>
            </Box>

            <Typography variant="body2" paragraph>
              {selectedFormatData.description}
            </Typography>

            <Typography variant="subtitle2" gutterBottom>
              Features included:
            </Typography>
            <List dense>
              {selectedFormatData.features.map((feature, index) => (
                <ListItem key={index} disableGutters>
                  <ListItemIcon style={{ minWidth: 30 }}>
                    <InfoIcon color="primary" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={feature} />
                </ListItem>
              ))}
            </List>

            {!selectedFormatData.available && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  This format is not yet available but is planned for a future release. 
                  Try the HTML format for the best reporting experience.
                </Typography>
              </Alert>
            )}
          </Box>
        )}

        {isExporting && (
          <Box mt={3}>
            <Typography variant="body2" gutterBottom>
              Generating your report...
            </Typography>
            <LinearProgress variant="determinate" value={exportProgress} />
            <Typography variant="caption" color="textSecondary">
              {exportProgress}% complete
            </Typography>
          </Box>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={isExporting}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleExport}
          disabled={!selectedFormatData?.available || isExporting}
          startIcon={isExporting ? undefined : <FileDownloadIcon />}
        >
          {isExporting ? 'Generating...' : 'Export Report'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ExportDialog;