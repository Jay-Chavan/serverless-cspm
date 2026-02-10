import React, { useState, useEffect } from 'react';
import {
    Box,
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
    Grid,
} from '@mui/material';
import {
    DataGrid,
    GridToolbarContainer,
    GridToolbarExport,
    GridToolbarFilterButton,
    GridToolbarColumnsButton,
} from '@mui/x-data-grid';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import VisibilityIcon from '@mui/icons-material/Visibility';
import FilterListIcon from '@mui/icons-material/FilterList';

const API_BASE_URL = 'http://localhost:5000/api';

const Findings = ({ filter = '' }) => {
    const navigate = useNavigate();
    const [findings, setFindings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [filters, setFilters] = useState({
        severity: filter || '',
        service: '',
        status: '',
        search: '',
    });
    const [pagination, setPagination] = useState({
        page: 0,
        pageSize: 10,
        total: 0,
    });

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
        fetchFindings();
    }, [pagination.page, pagination.pageSize, filters, filter]);

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
                    label={params.value}
                    color={getSeverityColor(params.value)}
                    size="small"
                    variant="filled"
                    sx={{ fontWeight: 600 }}
                />
            ),
        },
        { field: 'title', headerName: 'Title', flex: 1, minWidth: 250 },
        { field: 'service', headerName: 'Service', width: 100 },
        { field: 'resource_name', headerName: 'Resource', width: 180 },
        {
            field: 'status',
            headerName: 'Status',
            width: 130,
            renderCell: (params) => (
                <Chip
                    label={params.value}
                    color={getStatusColor(params.value)}
                    size="small"
                    variant="outlined"
                />
            ),
        },
        {
            field: 'actions',
            headerName: 'Actions',
            width: 90,
            sortable: false,
            renderCell: (params) => (
                <IconButton
                    size="small"
                    onClick={() => navigate(`/finding/${params.row._id}`)}
                    title="View Details"
                    color="primary"
                >
                    <VisibilityIcon />
                </IconButton>
            ),
        },
    ];

    const CustomToolbar = () => (
        <GridToolbarContainer sx={{ p: 1, gap: 1 }}>
            <GridToolbarColumnsButton />
            <GridToolbarFilterButton />
            <GridToolbarExport />
        </GridToolbarContainer>
    );

    return (
        <Box className="fade-in">
            <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h4" sx={{ color: 'text.primary' }}>
                    {filter === 'CRITICAL' ? 'Critical Security Issues' : 'All Security Findings'}
                </Typography>
            </Box>

            {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

            <Card className="glass-card" sx={{ mb: 4 }}>
                <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2, gap: 1 }}>
                        <FilterListIcon color="primary" />
                        <Typography variant="h6">Quick Filters</Typography>
                    </Box>
                    <Grid container spacing={3}>
                        <Grid item xs={12} sm={6} md={3}>
                            <TextField
                                fullWidth
                                label="Search Keywords"
                                variant="outlined"
                                value={filters.search}
                                onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                                sx={{ '& .MuiInputBase-root': { height: 56 } }}
                            />
                        </Grid>
                        {!filter && (
                            <Grid item xs={12} sm={6} md={4}>
                                <FormControl fullWidth>
                                    <InputLabel shrink>Severity Level</InputLabel>
                                    <Select
                                        value={filters.severity}
                                        label="Severity Level"
                                        onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                                        sx={{ height: 56 }}
                                        displayEmpty
                                        notched
                                    >
                                        <MenuItem value="">All Levels</MenuItem>
                                        <MenuItem value="Critical">Critical</MenuItem>
                                        <MenuItem value="High">High</MenuItem>
                                        <MenuItem value="Medium">Medium</MenuItem>
                                        <MenuItem value="Low">Low</MenuItem>
                                    </Select>
                                </FormControl>
                            </Grid>
                        )}
                        <Grid item xs={12} sm={6} md={4}>
                            <FormControl fullWidth>
                                <InputLabel shrink>AWS Service</InputLabel>
                                <Select
                                    value={filters.service}
                                    label="AWS Service"
                                    onChange={(e) => setFilters({ ...filters, service: e.target.value })}
                                    sx={{ height: 56 }}
                                    displayEmpty
                                    notched
                                >
                                    <MenuItem value="">All Services</MenuItem>
                                    <MenuItem value="S3">S3</MenuItem>
                                    <MenuItem value="KMS">KMS</MenuItem>
                                </Select>
                            </FormControl>
                        </Grid>
                    </Grid>
                </CardContent>
            </Card>

            <Card className="glass-card">
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
                        }}
                        disableSelectionOnClick
                        sx={{
                            border: 'none',
                            '& .MuiDataGrid-cell:focus': { outline: 'none' },
                            '& .MuiDataGrid-columnHeader:focus': { outline: 'none' },
                        }}
                    />
                </Box>
            </Card>
        </Box>
    );
};

export default Findings;
