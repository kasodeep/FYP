const cron = require('node-cron');
const path = require('path');
const fs = require('fs').promises;
const { createReadStream } = require('fs');
const readline = require('readline');

// In-memory cache for latest logs
let latestLogs = [];
const MAX_LOGS = 20;

function initZeekReader() {
  const zeekPath = process.env.ZEEK_LOG_PATH || '/usr/local/zeek/logs/current/';
  
  // Initial read
  readZeekLogs(zeekPath);

  // Schedule log reading every 30 seconds
  cron.schedule('*/30 * * * * *', () => {
    readZeekLogs(zeekPath);
  });
}

async function readZeekLogs(logPath) {
  try {
    const logTypes = ['conn.log', 'http.log', 'dns.log'];
    const newLogs = [];

    for (const logType of logTypes) {
      const filePath = path.join(logPath, logType);
      try {
        const logs = await readLastNLines(filePath, 20);
        const parsedLogs = logs.map(log => parseZeekLog(log, logType)).filter(log => log !== null);
        newLogs.push(...parsedLogs);
      } catch (error) {
        console.error(`Error reading ${logType}:`, error);
      }
    }

    // Replace the entire logs collection with the new sorted logs
    latestLogs = newLogs
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, MAX_LOGS);

  } catch (error) {
    console.error('Error processing Zeek logs:', error);
  }
}

async function readLastNLines(filePath, n) {
  try {
    const fileStream = createReadStream(filePath);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    const lines = [];
    for await (const line of rl) {
      if (!line.startsWith('#')) {  // Skip header lines
        lines.push(line);
        if (lines.length > n) {
          lines.shift();
        }
      }
    }

    return lines;
  } catch (error) {
    console.error(`Error reading file ${filePath}:`, error);
    return [];
  }
}

function parseZeekLog(line, logType) {
  const fields = line.split('\t');
  
  try {
    switch (logType) {
      case 'conn.log':
        return {
          type: 'conn',
          timestamp: new Date(fields[0] * 1000).toISOString(),
          source: fields[2],
          destination: fields[4],
          protocol: fields[6],
          event: `Connection ${fields[11]}` // Connection state
        };

      case 'http.log':
        return {
          type: 'http',
          timestamp: new Date(fields[0] * 1000).toISOString(),
          source: fields[2],
          destination: fields[4],
          protocol: 'HTTP',
          event: `${fields[7]} ${fields[9]}` // Method URI
        };

      case 'dns.log':
        return {
          type: 'dns',
          timestamp: new Date(fields[0] * 1000).toISOString(),
          source: fields[2],
          destination: fields[4],
          protocol: 'DNS',
          event: `Query: ${fields[9]}` // Query
        };

      default:
        return null;
    }
  } catch (error) {
    console.error(`Error parsing ${logType}:`, error);
    return null;
  }
}

function getLatestLogs(types = []) {
  // Return empty array if latestLogs is not an array
  if (!Array.isArray(latestLogs)) {
    return [];
  }

  const validLogs = latestLogs.filter(log => 
    log && 
    log.type && 
    log.timestamp && 
    (types.length === 0 || types.includes(log.type))
  );
  
  return validLogs;
}

function getAvailableLogTypes() {
  return ['conn', 'http', 'dns'];
}

module.exports = {
  initZeekReader,
  getLatestLogs,
  getAvailableLogTypes
};