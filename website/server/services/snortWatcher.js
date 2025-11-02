const chokidar = require('chokidar');
const path = require('path');
const fs = require('fs').promises;
const readline = require('readline');
const { createReadStream } = require('fs');

function initSnortWatcher(io) {
  const snortPath = process.env.SNORT_ALERT_PATH || path.join(__dirname, '..', '..', 'test-data', 'snort', 'logs', 'alert');
  
  console.log('Watching Snort alerts at:', snortPath);
  
  // Initial read of existing alerts
  readExistingAlerts(snortPath, io).then(() => {
    console.log('Initial Snort alerts processed');
  }).catch(error => {
    console.error('Error during initial alert processing:', error);
  });

  // Watch for new alerts
  const watcher = chokidar.watch(snortPath, {
    persistent: true,
    usePolling: true,
    awaitWriteFinish: {
      stabilityThreshold: 2000,
      pollInterval: 100
    }
  });

  watcher.on('change', (path) => {
    console.log('Detected change in alert file:', path);
    processNewAlerts(path, io);
  });
}

async function readExistingAlerts(filePath, io) {
  try {
    console.log('Attempting to read alerts from:', filePath);
    
    // Check if file exists
    await fs.access(filePath).catch(() => {
      throw new Error(`Alert file not found at ${filePath}`);
    });

    const fileStream = createReadStream(filePath);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    let alerts = [];
    for await (const line of rl) {
      console.log('Processing line:', line);
      const alert = parseAlertLine(line);
      if (alert) {
        console.log('Parsed alert:', alert);
        alerts.push(alert);
      }
    }

    console.log(`Found ${alerts.length} alerts`);

    // Emit existing alerts in reverse chronological order
    alerts.reverse().forEach(alert => {
      console.log('Emitting alert:', alert);
      io.emit('newAlert', alert);
      require('../routes/snortRoutes').addAlert(alert);
      require('../routes/chartRoutes').addAlertToHistory(alert, io);
    });
  } catch (error) {
    console.error('Error reading existing alerts:', error);
    throw error;
  }
}

async function processNewAlerts(filePath, io) {
  try {
    console.log('Processing new alerts from:', filePath);
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    
    // Process only the last line as it's likely the new alert
    const lastLine = lines[lines.length - 2]; // -2 to skip empty last line
    if (lastLine) {
      console.log('Processing new line:', lastLine);
      const alert = parseAlertLine(lastLine);
      if (alert) {
        console.log('New alert parsed:', alert);
        io.emit('newAlert', alert);
        require('../routes/snortRoutes').addAlert(alert);
        require('../routes/chartRoutes').addAlertToHistory(alert, io);
      }
    }
  } catch (error) {
    console.error('Error processing new alert:', error);
  }
}

function parseAlertLine(line) {
  // Example Snort alert format:
  // [**] [1:1000:1] SNMP Trap TCP [**] [Priority: 2] {TCP} 192.168.1.1:1024 -> 10.0.0.1:161
  try {
    const parts = line.split('[**]');
    if (parts.length < 2) return null;

    // Extract the message from between the SID and Priority sections
    const messageMatch = line.match(/\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]/);
    const message = messageMatch ? messageMatch[1].trim() : 'Unknown Alert';
    
    // Extract SID
    const sidMatch = line.match(/\[(\d+:\d+:\d+)\]/);
    const sid = sidMatch ? sidMatch[1] : 'unknown';
    
    const priorityMatch = line.match(/\[Priority:\s*(\d+)\]/);
    const priority = priorityMatch ? parseInt(priorityMatch[1]) : 0;
    
    const ipMatch = line.match(/{\w+}\s+([0-9.]+):(\d+)\s+->\s+([0-9.]+):(\d+)/);
    const protocolMatch = line.match(/{(\w+)}/);
    
    let severity = 'low';
    if (priority >= 2) severity = 'medium';
    if (priority >= 3) severity = 'high';

    const alert = {
      timestamp: new Date().toISOString(),
      sourceIp: ipMatch ? ipMatch[1] : 'unknown',
      sourcePort: ipMatch ? ipMatch[2] : 'unknown',
      destinationIp: ipMatch ? ipMatch[3] : 'unknown',
      destinationPort: ipMatch ? ipMatch[4] : 'unknown',
      protocol: protocolMatch ? protocolMatch[1] : 'unknown',
      message: message || 'Unknown Alert',
      severity,
      sid
    };

    // Add to chart history immediately
    require('../routes/chartRoutes').addAlertToHistory(alert);
    
    return alert;
  } catch (error) {
    console.error('Error parsing alert line:', error);
    return null;
  }
}

module.exports = {
  initSnortWatcher
};