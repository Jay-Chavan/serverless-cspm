import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  TextField,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  Chip,
  IconButton,
  Alert,
  CircularProgress,
} from '@mui/material';
import {
  DataGrid,
  GridToolbarContainer,
  GridToolbarExport,
  GridToolbarFilterButton,
  GridToolbarColumnsButton,
} from '@mui/x-data-grid';
// import SecurityIcon from '@mui/icons-material/Security';
// import WarningIcon from '@mui/icons-material/Warning';
// import ErrorIcon from '@mui/icons-material/Error';
// import CheckCircleIcon from '@mui/icons-material/CheckCircle';
// import VisibilityIcon from '@mui/icons-material/Visibility';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const Dashboard = () => {
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    severity: '',
    service: '',
    status: '',
    search: '',
  });
  const [pagination, setPagination] = useState({
    page: 0,
    pageSize: 10,
    total: 0,
  });

  // Fetch dashboard statistics
  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/stats`);
      setStats(response.data);
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  };

  // Fetch findings with filters and pagination
  const fetchFindings = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: pagination.page + 1,
        limit: pagination.pageSize,
        ...Object.fromEntries(Object.entries(filters).filter(([_, v]) => v)),
      });

      const response = await axios.get(`${API_BASE_URL}/findings?${params}`);
      setFindings(response.data.findings);
      setPagination(prev => ({
        ...prev,
        total: response.data.pagination.total,
      }));
      setError(null);
    } catch (err) {
      setError('Failed to fetch findings. Please check if the backend server is running.');
      console.error('Error fetching findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchFindings();
  }, [pagination.page, pagination.pageSize, filters]);

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'open': return 'error';
      case 'in_progress': return 'warning';
      case 'resolved': return 'success';
      case 'false_positive': return 'default';
      default: return 'default';
    }
  };

  const columns = [
    {
      field: 'severity',
      headerName: 'Severity',
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params?.value || 'Unknown'}
          color={getSeverityColor(params?.value)}
          size="small"
          variant="outlined"
        />
      ),
    },
    {
      field: 'title',
      headerName: 'Title',
      width: 300,
      flex: 1,
    },
    {
      field: 'service',
      headerName: 'Service',
      width: 120,
    },
    {
      field: 'resource_id',
      headerName: 'Resource ID',
      width: 200,
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params?.value || 'Unknown'}
          color={getStatusColor(params?.value)}
          size="small"
        />
      ),
    },
    {
      field: 'timestamp',
      headerName: 'Detected',
      width: 180,
      valueFormatter: (params) => {
        if (!params?.value) return 'N/A';
        return new Date(params.value).toLocaleString();
      },
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 100,
      sortable: false,
      renderCell: (params) => (
        <IconButton
          size="small"
          onClick={() => navigate(`/finding/${params?.row?._id}`)}
          title="View Details"
        >
          👁️
        </IconButton>
      ),
    },
  ];

  const CustomToolbar = () => (
    <GridToolbarContainer>
      <GridToolbarColumnsButton />
      <GridToolbarFilterButton />
      <GridToolbarExport />
    </GridToolbarContainer>
  );

  const StatCard = ({ title, value, icon, color = 'primary' }) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography color="textSecondary" gutterBottom variant="overline">
              {title}
            </Typography>
            <Typography variant="h4" component="div">
              {value || 0}
            </Typography>
          </Box>
          <Box sx={{ color: `${color}.main` }}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        <Typography variant="body1">
          Make sure the Flask backend server is running on http://localhost:5000
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Security Findings Dashboard
      </Typography>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Findings"
            value={stats?.total_findings}
            icon="🔒"
            color="primary"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Recent (7 days)"
            value={stats?.recent_findings}
            icon="⚠️"
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Critical Issues"
            value={stats?.severity_distribution?.find(s => s._id === 'CRITICAL')?.count}
            icon="❌"
            color="error"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Resolved"
            value={stats?.status_distribution?.find(s => s._id === 'resolved')?.count}
            icon="✅"
            color="success"
          />
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Filters
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <TextField
                fullWidth
                label="Search"
                value={filters.search || ''}
                onChange={(e) => setFilters({ ...filters, search: e?.target?.value || '' })}
                placeholder="Search findings..."
              />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={filters.severity || ''}
                  label="Severity"
                  onChange={(e) => setFilters({ ...filters, severity: e?.target?.value || '' })}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="CRITICAL">Critical</MenuItem>
                  <MenuItem value="HIGH">High</MenuItem>
                  <MenuItem value="MEDIUM">Medium</MenuItem>
                  <MenuItem value="LOW">Low</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Service</InputLabel>
                <Select
                  value={filters.service || ''}
                  label="Service"
                  onChange={(e) => setFilters({ ...filters, service: e?.target?.value || '' })}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="S3">S3</MenuItem>
                  <MenuItem value="EC2">EC2</MenuItem>
                  <MenuItem value="IAM">IAM</MenuItem>
                  <MenuItem value="RDS">RDS</MenuItem>
                  <MenuItem value="KMS">KMS</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={filters.status || ''}
                  label="Status"
                  onChange={(e) => setFilters({ ...filters, status: e?.target?.value || '' })}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="open">Open</MenuItem>
                  <MenuItem value="in_progress">In Progress</MenuItem>
                  <MenuItem value="resolved">Resolved</MenuItem>
                  <MenuItem value="false_positive">False Positive</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Findings Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Security Findings
          </Typography>
          <Box sx={{ height: 600, width: '100%' }}>
            <DataGrid
              rows={findings}
              columns={columns}
              getRowId={(row) => row._id}
              paginationMode="server"
              rowCount={pagination.total}
              page={pagination.page}
              pageSize={pagination.pageSize}
              onPageChange={(newPage) => setPagination(prev => ({ ...prev, page: newPage }))}
              onPageSizeChange={(newPageSize) => setPagination(prev => ({ ...prev, pageSize: newPageSize }))}
              loading={loading}
              components={{
                Toolbar: CustomToolbar,
                LoadingOverlay: () => (
                  <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                    <CircularProgress />
                  </Box>
                ),
              }}
              disableSelectionOnClick
              sx={{
                '& .MuiDataGrid-row:hover': {
                  cursor: 'pointer',
                },
              }}
              onRowClick={(params) => navigate(`/finding/${params.row._id}`)}
            />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default Dashboard;