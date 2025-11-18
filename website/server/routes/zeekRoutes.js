const express = require('express');
const router = express.Router();
const { getLatestLogs } = require('../services/zeekReader');

// Get latest logs
router.get('/logs/latest', async (req, res) => {
  try {
    const types = req.query.types ? req.query.types.split(',') : [];
    const logs = getLatestLogs(types);
    res.json({ logs });
  } catch (error) {
    console.error('Error in /logs/latest:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get Zeek statistics
router.get('/stats', async (req, res) => {
  try {
    const logs = getLatestLogs();
    const stats = {
      protocols: {},
      sourceIps: {},
      totalConnections: logs.length
    };

    // Calculate statistics
    logs.forEach(log => {
      // Count protocols
      stats.protocols[log.protocol] = (stats.protocols[log.protocol] || 0) + 1;
      
      // Count source IPs
      stats.sourceIps[log.source] = (stats.sourceIps[log.source] || 0) + 1;
    });

    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;