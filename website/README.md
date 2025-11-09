# Network Security Monitoring Dashboard

A real-time network security monitoring dashboard that visualizes data from Snort (intrusion detection alerts) and Zeek (network activity logs).

## Features

- Real-time streaming of Snort alerts
- Display of latest Zeek logs
- Analytical charts summarizing trends
- Modern responsive dashboard UI with light/dark mode
- WebSocket integration for live updates

## Tech Stack

### Frontend

- React 18+ with Vite
- Tailwind CSS for styling
- pnpm for package management
- Axios for API calls
- Recharts for visualization
- WebSocket client for real-time data
- Framer Motion for animations

### Backend

- Node.js (v18+) with Express.js
- Chokidar for file monitoring
- WebSocket (socket.io) for real-time updates
- node-cron for periodic tasks
- dotenv for configuration

## Project Structure

```
/
├── client/              # React frontend
│   ├── src/
│   │   ├── components/  # Reusable UI components
│   │   ├── pages/      # Page components
│   │   └── utils/      # Utility functions
│   └── ...
├── server/             # Node.js backend
│   ├── routes/        # API routes
│   ├── services/      # Business logic
│   └── ...
└── ...
```

## Setup Instructions

1. Install dependencies:

   ```bash
   pnpm install:all
   ```

2. Configure environment variables:

   - Copy `.env.example` to `.env` in the server directory
   - Update the paths for Snort and Zeek logs

3. Start development servers:

   ```bash
   # Start both client and server
   pnpm dev

   # Or start individually:
   pnpm client  # Start React dev server
   pnpm server  # Start Node.js server
   ```

4. Access the application:
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:5000

## Available Scripts

- `pnpm dev` - Start both client and server in development mode
- `pnpm client` - Start the React development server
- `pnpm server` - Start the Node.js server
- `pnpm build` - Build the frontend for production
- `pnpm install:all` - Install dependencies for all packages

## Environment Variables

### Server (.env)

```
PORT=5000
CLIENT_URL=http://localhost:5173
SNORT_ALERT_PATH=/var/log/snort/alert
ZEEK_LOG_PATH=/usr/local/zeek/logs/current/
```

## License

This project is licensed under the ISC License.
