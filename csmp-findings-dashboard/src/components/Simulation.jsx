
import React, { useState } from 'react';
import {
    Box,
    Card,
    CardContent,
    Typography,
    Button,
    Alert,
    LinearProgress,
    Stack,
    TextField,
    Divider
} from '@mui/material';
import axios from 'axios';
import SecurityIcon from '@mui/icons-material/Security';
import DeleteIcon from '@mui/icons-material/Delete';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';

const API_BASE_URL = 'http://localhost:5000/api';

const Simulation = () => {
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [activeResource, setActiveResource] = useState(null);

    const handleSimulateS3 = async () => {
        setLoading(true);
        setError(null);
        setResult(null);
        try {
            const response = await axios.post(`${API_BASE_URL}/simulate/s3`);
            setResult(response.data);
            setActiveResource(response.data.resource_id);
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleCleanup = async () => {
        if (!activeResource) return;

        setLoading(true);
        try {
            const response = await axios.post(`${API_BASE_URL}/simulate/cleanup`, {
                resource_id: activeResource
            });
            setResult(null);
            setActiveResource(null);
            alert("Resource cleaned up successfully");
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box className="fade-in" sx={{ maxWidth: 800, mx: 'auto', mt: 4 }}>
            <Box sx={{ mb: 4, textAlign: 'center' }}>
                <AutoFixHighIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h4" sx={{ color: 'text.primary', mb: 1 }}>
                    Vulnerability Simulation Control
                </Typography>
                <Typography variant="body1" sx={{ color: 'text.secondary' }}>
                    Authorized Personnel Only. Triggers real infrastructure changes.
                </Typography>
            </Box>

            <Card className="glass-card" sx={{ mb: 4, border: '1px solid rgba(255, 127, 17, 0.3)' }}>
                <CardContent>
                    <Stack spacing={3}>
                        <Box>
                            <Typography variant="h6" gutterBottom>
                                Scenario 1: Public S3 Bucket
                            </Typography>
                            <Typography variant="body2" color="text.secondary" paragraph>
                                Creates a new S3 bucket with a randomized name (starting with cspm-demo-)
                                and applies a public bucket policy. This should trigger the S3 Security Auditor Lambda.
                            </Typography>

                            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                                <Button
                                    variant="contained"
                                    color="warning"
                                    size="large"
                                    onClick={handleSimulateS3}
                                    disabled={loading || activeResource}
                                    startIcon={<SecurityIcon />}
                                >
                                    {loading ? 'Simulating...' : 'Create Vulnerable Bucket'}
                                </Button>

                                <Button
                                    variant="outlined"
                                    color="error"
                                    size="large"
                                    onClick={handleCleanup}
                                    disabled={loading || !activeResource}
                                    startIcon={<DeleteIcon />}
                                >
                                    Cleanup Resource
                                </Button>
                            </Box>
                        </Box>

                        {loading && <LinearProgress color="warning" />}

                        {error && (
                            <Alert severity="error" sx={{ mt: 2 }}>
                                {error}
                            </Alert>
                        )}

                        {result && (
                            <Alert severity="success" sx={{ mt: 2 }}>
                                <Typography variant="subtitle1" fontWeight="bold">
                                    Simulation Active
                                </Typography>
                                <Typography variant="body2">
                                    Resource created: <strong>{result.resource_id}</strong>
                                </Typography>
                                <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                                    Region: {result.region} | Auto-cleanup scheduled in 15m
                                </Typography>
                            </Alert>
                        )}

                        <Divider />

                        <Alert severity="info" icon={false}>
                            <strong>Instructions for Demo:</strong>
                            <ol>
                                <li>Click "Create Vulnerable Bucket".</li>
                                <li>Wait for "Simulation Active" message.</li>
                                <li>Switch to the main dashboard tab.</li>
                                <li>Wait for the Lambda to detect the issue (approx 1-2 mins).</li>
                                <li>Refresh the dashboard to see the real-time finding.</li>
                                <li>Come back here and click "Cleanup Resource" when done.</li>
                            </ol>
                        </Alert>
                    </Stack>
                </CardContent>
            </Card>
        </Box>
    );
};

export default Simulation;
