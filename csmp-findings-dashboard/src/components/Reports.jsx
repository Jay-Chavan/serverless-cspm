import React, { useState, useEffect } from 'react';
import {
    Box,
    Typography,
    Grid,
    Card,
    CardContent,
    Button,
    Divider,
    List,
    ListItem,
    ListItemText,
    ListItemIcon,
    Avatar,
    IconButton,
    CircularProgress,
    Alert,
} from '@mui/material';
import AssessmentIcon from '@mui/icons-material/Assessment';
import DownloadIcon from '@mui/icons-material/Download';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import PrintIcon from '@mui/icons-material/Print';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const Reports = () => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchStats();
    }, []);

    const fetchStats = async () => {
        try {
            const response = await axios.get(`${API_BASE_URL}/stats`);
            setStats(response.data);
            setError(null);
        } catch (err) {
            setError('Failed to fetch statistics');
            console.error('Error fetching stats:', err);
        } finally {
            setLoading(false);
        }
    };

    const calculateComplianceScore = () => {
        if (!stats) return 0;
        const total = stats.total_findings || 0;
        const resolved = stats.status_distribution?.find(s => s._id === 'Resolved')?.count || 0;
        const critical = stats.severity_distribution?.find(s => s._id === 'Critical')?.count || 0;

        if (total === 0) return 100;

        // Score calculation: base 100, minus points for unresolved and critical
        const unresolvedPenalty = ((total - resolved) / total) * 30;
        const criticalPenalty = (critical / total) * 20;

        return Math.max(0, Math.round(100 - unresolvedPenalty - criticalPenalty));
    };

    const getTopViolations = () => {
        if (!stats) return [];

        const violations = [];

        // S3 public buckets
        const s3Count = stats.service_distribution?.find(s => s._id === 'S3')?.count || 0;
        if (s3Count > 0) {
            violations.push({
                text: `S3 Security Issues (${s3Count})`,
                type: 'warning',
            });
        }

        // KMS findings
        const kmsCount = stats.service_distribution?.find(s => s._id === 'KMS')?.count || 0;
        if (kmsCount > 0) {
            violations.push({
                text: `KMS Key Rotation Issues (${kmsCount})`,
                type: 'warning',
            });
        }

        // Add a positive finding
        const resolvedCount = stats.status_distribution?.find(s => s._id === 'Resolved')?.count || 0;
        if (resolvedCount > 0) {
            violations.push({
                text: `Issues Resolved (${resolvedCount})`,
                type: 'success',
            });
        }

        return violations;
    };

    const reportTemplates = [
        {
            title: 'Executive Security Summary',
            description: 'High-level overview of security posture for management.',
            lastGenerated: new Date().toLocaleDateString(),
            status: 'Ready',
        },
        {
            title: 'S3 Security & Access Audit',
            description: 'Detailed analysis of S3 bucket policies and public access.',
            lastGenerated: new Date().toLocaleDateString(),
            status: 'Ready',
        },
        {
            title: 'KMS Key Management Report',
            description: 'Compliance report for KMS key rotation and encryption.',
            lastGenerated: new Date().toLocaleDateString(),
            status: 'Ready',
        },
    ];

    if (loading) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
                <CircularProgress />
            </Box>
        );
    }

    const complianceScore = calculateComplianceScore();
    const topViolations = getTopViolations();
    const criticalCount = stats?.severity_distribution?.find(s => s._id === 'Critical')?.count || 0;

    return (
        <Box className="fade-in">
            <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h4" sx={{ color: 'text.primary' }}>
                    Security & Compliance Reports
                </Typography>
                <Button
                    variant="contained"
                    startIcon={<AssessmentIcon />}
                    sx={{ borderRadius: 10 }}
                    onClick={fetchStats}
                >
                    Refresh Data
                </Button>
            </Box>

            {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

            <Grid container spacing={3}>
                <Grid item xs={12} md={8}>
                    <Card className="glass-card">
                        <CardContent>
                            <Typography variant="h6" gutterBottom>Available Templates</Typography>
                            <List>
                                {reportTemplates.map((report, index) => (
                                    <React.Fragment key={index}>
                                        <ListItem
                                            sx={{ py: 2 }}
                                            secondaryAction={
                                                <Box>
                                                    <IconButton color="primary"><DownloadIcon /></IconButton>
                                                    <IconButton><PrintIcon /></IconButton>
                                                </Box>
                                            }
                                        >
                                            <ListItemIcon>
                                                <Avatar sx={{ bgcolor: report.status === 'Ready' ? 'secondary.main' : 'warning.main' }}>
                                                    <AssessmentIcon />
                                                </Avatar>
                                            </ListItemIcon>
                                            <ListItemText
                                                primary={report.title}
                                                secondary={`${report.description} • Last updated: ${report.lastGenerated}`}
                                                primaryTypographyProps={{ fontWeight: 600 }}
                                            />
                                        </ListItem>
                                        {index < reportTemplates.length - 1 && <Divider component="li" />}
                                    </React.Fragment>
                                ))}
                            </List>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} md={4}>
                    <Card className="glass-card" sx={{ height: '100%', bgcolor: '#262626', color: '#E2E8CE' }}>
                        <CardContent>
                            <Typography variant="h6" gutterBottom color="#FF7F11">Compliance Score</Typography>
                            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4 }}>
                                <Typography variant="h2" sx={{ fontWeight: 800 }}>{complianceScore}%</Typography>
                                <Typography variant="body2" sx={{ opacity: 0.7 }}>
                                    Based on {stats?.total_findings || 0} findings
                                </Typography>
                            </Box>
                            <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.1)' }} />
                            <Typography variant="subtitle2" gutterBottom>Current Status</Typography>
                            <List size="small">
                                {topViolations.map((violation, idx) => (
                                    <ListItem dense key={idx}>
                                        <ListItemIcon sx={{ minWidth: 30 }}>
                                            {violation.type === 'warning' ? (
                                                <WarningAmberIcon sx={{ color: '#FF7F11', fontSize: 18 }} />
                                            ) : (
                                                <CheckCircleOutlineIcon sx={{ color: '#ACBFA4', fontSize: 18 }} />
                                            )}
                                        </ListItemIcon>
                                        <ListItemText primary={violation.text} />
                                    </ListItem>
                                ))}
                                {criticalCount > 0 && (
                                    <ListItem dense>
                                        <ListItemIcon sx={{ minWidth: 30 }}>
                                            <WarningAmberIcon sx={{ color: '#FF7F11', fontSize: 18 }} />
                                        </ListItemIcon>
                                        <ListItemText
                                            primary={`Critical Issues (${criticalCount})`}
                                            sx={{ color: '#FF7F11', fontWeight: 600 }}
                                        />
                                    </ListItem>
                                )}
                            </List>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>
        </Box>
    );
};

export default Reports;
