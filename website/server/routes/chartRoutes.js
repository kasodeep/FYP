const express = require('express');
const router = express.Router();

// In-memory store for alerts (in production, use a proper database)
let alertsHistory = [];
const MAX_HISTORY = 1000; // Keep last 1000 alerts for statistics

// Function to add alert to history
function addAlertToHistory(alert, io = null) {
  alertsHistory.unshift(alert);
  if (alertsHistory.length > MAX_HISTORY) {
    alertsHistory.pop();
  }

  // If socket.io instance is provided, emit updated chart data
  if (io) {
    const severityData = getSeverityData();
    const trendData = getTrendData();
    const protocolData = getProtocolData();

    io.emit('chartData', {
      severity: severityData,
      trend: trendData,
      protocols: protocolData
    });
  }
}

// Helper functions for chart data
function getSeverityData() {
  const severityCounts = {
    high: 0,
    medium: 0,
    low: 0
  };

  alertsHistory.forEach(alert => {
    severityCounts[alert.severity]++;
  });

  return Object.entries(severityCounts).map(([name, value]) => ({
    name,
    value
  }));
}

function getTrendData() {
  const now = new Date();
  const hourly = new Array(24).fill(0);
  
  alertsHistory.forEach(alert => {
    const alertTime = new Date(alert.timestamp);
    const hoursDiff = Math.floor((now - alertTime) / (1000 * 60 * 60));
    if (hoursDiff < 24) {
      hourly[23 - hoursDiff]++;
    }
  });

  return hourly.map((count, i) => ({
    time: `${23-i}h ago`,
    count
  }));
}

function getProtocolData() {
  const protocolCounts = {};
  
  alertsHistory.forEach(alert => {
    protocolCounts[alert.protocol] = (protocolCounts[alert.protocol] || 0) + 1;
  });

  return Object.entries(protocolCounts).map(([name, value]) => ({
    name,
    value
  }));
}

// Get alerts by severity
router.get('/alerts-severity', async (req, res) => {
  try {
    const severityCounts = {
      high: 0,
      medium: 0,
      low: 0
    };

    alertsHistory.forEach(alert => {
      severityCounts[alert.severity]++;
    });

    const data = Object.entries(severityCounts).map(([name, value]) => ({
      name,
      value
    }));

    res.json({ data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get alerts trend
router.get('/alerts-trend', async (req, res) => {
  try {
    const now = new Date();
    const hourly = new Array(24).fill(0);
    
    alertsHistory.forEach(alert => {
      const alertTime = new Date(alert.timestamp);
      const hoursDiff = Math.floor((now - alertTime) / (1000 * 60 * 60));
      if (hoursDiff < 24) {
        hourly[23 - hoursDiff]++;
      }
    });

    const data = hourly.map((count, i) => ({
      time: `${23-i}h ago`,
      count
    }));

    res.json({ data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get protocols distribution
router.get('/protocols', async (req, res) => {
  try {
    const protocolCounts = {};
    
    alertsHistory.forEach(alert => {
      protocolCounts[alert.protocol] = (protocolCounts[alert.protocol] || 0) + 1;
    });

    const data = Object.entries(protocolCounts).map(([name, value]) => ({
      name,
      value
    }));

    res.json({ data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = {
  router,
  addAlertToHistory
};