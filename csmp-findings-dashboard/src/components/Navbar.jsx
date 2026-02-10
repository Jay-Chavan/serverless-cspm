import React, { useState, useEffect } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Badge,
  Box,
  Menu,
  MenuItem,
  ListItemText,
  Divider,
  Chip,
} from '@mui/material';
import NotificationsIcon from '@mui/icons-material/Notifications';
import SecurityIcon from '@mui/icons-material/Security';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const Navbar = () => {
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [notificationCount, setNotificationCount] = useState(0);

  useEffect(() => {
    fetchNotifications();
    // Refresh notifications every 30 seconds
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchNotifications = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/findings?severity=Critical&limit=5`);
      const criticalFindings = response.data.findings || [];
      setNotifications(criticalFindings);
      setNotificationCount(criticalFindings.length);
    } catch (err) {
      console.error('Error fetching notifications:', err);
    }
  };

  const handleNotificationClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleNotificationItemClick = (findingId) => {
    handleClose();
    navigate(`/finding/${findingId}`);
  };

  const handleRefresh = () => {
    fetchNotifications();
    window.location.reload();
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      default: return 'default';
    }
  };

  return (
    <AppBar
      position="fixed"
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        backgroundColor: '#262626',
        boxShadow: '0 2px 10px rgba(0,0,0,0.3)',
      }}
    >
      <Toolbar>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            cursor: 'pointer',
            '&:hover': { opacity: 0.8 }
          }}
          onClick={() => navigate('/')}
        >
          <SecurityIcon
            sx={{
              mr: 2,
              color: '#FF7F11',
              filter: 'drop-shadow(0 0 2px #FF7F11)'
            }}
            className="animate-glow"
          />
          <Typography
            variant="h6"
            component="div"
            sx={{
              fontWeight: 700,
              letterSpacing: 0.5,
              color: '#E2E8CE'
            }}
          >
            Serverless CSPM
          </Typography>
        </Box>

        <Box sx={{ flexGrow: 1 }} />

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <IconButton
            color="inherit"
            title="Refresh Data"
            sx={{ color: '#ACBFA4' }}
            onClick={handleRefresh}
          >
            <RefreshIcon />
          </IconButton>

          <IconButton
            color="inherit"
            title="Notifications"
            sx={{ color: '#ACBFA4' }}
            onClick={handleNotificationClick}
          >
            <Badge badgeContent={notificationCount} color="error">
              <NotificationsIcon />
            </Badge>
          </IconButton>

          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={handleClose}
            PaperProps={{
              sx: {
                mt: 1,
                width: 360,
                maxHeight: 400,
                bgcolor: '#262626',
                color: '#E2E8CE',
                border: '1px solid rgba(255, 127, 17, 0.2)',
              }
            }}
          >
            <Box sx={{ px: 2, py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
              <Typography variant="h6" sx={{ color: '#FF7F11' }}>
                Critical Alerts
              </Typography>
              <Typography variant="caption" sx={{ opacity: 0.7 }}>
                {notificationCount} critical {notificationCount === 1 ? 'issue' : 'issues'} require attention
              </Typography>
            </Box>

            {notifications.length === 0 ? (
              <MenuItem disabled>
                <ListItemText primary="No critical findings" />
              </MenuItem>
            ) : (
              notifications.map((finding, index) => (
                <React.Fragment key={finding._id}>
                  <MenuItem
                    onClick={() => handleNotificationItemClick(finding._id)}
                    sx={{
                      py: 1.5,
                      '&:hover': { bgcolor: 'rgba(255, 127, 17, 0.1)' }
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                          <Chip
                            label={finding.severity}
                            color={getSeverityColor(finding.severity)}
                            size="small"
                            sx={{ height: 20, fontSize: '0.7rem' }}
                          />
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {finding.service}
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <Typography variant="caption" sx={{ color: '#ACBFA4' }}>
                          {finding.title}
                        </Typography>
                      }
                    />
                  </MenuItem>
                  {index < notifications.length - 1 && <Divider sx={{ bgcolor: 'rgba(255,255,255,0.05)' }} />}
                </React.Fragment>
              ))
            )}

            <Divider sx={{ bgcolor: 'rgba(255,255,255,0.1)' }} />
            <MenuItem
              onClick={() => { handleClose(); navigate('/critical'); }}
              sx={{
                justifyContent: 'center',
                color: '#FF7F11',
                fontWeight: 600,
                '&:hover': { bgcolor: 'rgba(255, 127, 17, 0.1)' }
              }}
            >
              View All Critical Issues
            </MenuItem>
          </Menu>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;