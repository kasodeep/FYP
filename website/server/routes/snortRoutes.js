const express = require('express');
const router = express.Router();

// In-memory store for latest alerts (in production, use a proper database)
let latestAlerts = [];
const MAX_ALERTS = 50;

// Add new alert to the store
function addAlert(alert) {
  latestAlerts.unshift(alert);
  if (latestAlerts.length > MAX_ALERTS) {
    latestAlerts.pop();
  }
  
  // Also add to chart statistics
  require('./chartRoutes').addAlertToHistory(alert);
}

// Get latest alerts
router.get('/alerts/latest', async (req, res) => {
  try {
    res.json({ alerts: latestAlerts });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get alert statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = {
      total: latestAlerts.length,
      bySeverity: {
        high: 0,
        medium: 0,
        low: 0
      },
      byProtocol: {},
      topSourceIps: {},
      topDestinationIps: {}
    };

    latestAlerts.forEach(alert => {
      // Count by severity
      stats.bySeverity[alert.severity]++;
      
      // Count by protocol
      stats.byProtocol[alert.protocol] = (stats.byProtocol[alert.protocol] || 0) + 1;
      
      // Count source IPs
      stats.topSourceIps[alert.sourceIp] = (stats.topSourceIps[alert.sourceIp] || 0) + 1;
      
      // Count destination IPs
      stats.topDestinationIps[alert.destinationIp] = 
        (stats.topDestinationIps[alert.destinationIp] || 0) + 1;
    });

    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = {
  router,
  addAlert
};