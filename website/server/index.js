require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const { initSnortWatcher } = require('./services/snortWatcher');
const { initZeekReader } = require('./services/zeekReader');

// Get route modules
const snortRoutes = require('./routes/snortRoutes');
const zeekRoutes = require('./routes/zeekRoutes');
const chartRoutes = require('./routes/chartRoutes');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Routes
app.use('/api/snort', snortRoutes.router);
app.use('/api/zeek', zeekRoutes);
app.use('/api/charts', chartRoutes.router);

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log('Client connected');
  
  // Send initial data on connection
  socket.emit('systemInfo', {
    startTime: new Date().toISOString(),
    snortPath: process.env.SNORT_ALERT_PATH || '/var/log/snort/alert',
    zeekPath: process.env.ZEEK_LOG_PATH || '/usr/local/zeek/logs/current/'
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Initialize watchers with alert handlers
initSnortWatcher(io);
initZeekReader();

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server ready`);
  console.log(`API Documentation available at /api-docs`);
});