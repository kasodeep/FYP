import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { Toaster } from 'react-hot-toast';
import AlertsTable from './components/AlertsTable';
import ZeekLogsTable from './components/ZeekLogsTable';
import Charts from './components/Charts';
import Footer from './components/Footer';
import Navbar from './components/Navbar';
import { onSystemInfo } from './utils/socket';

function Dashboard() {
  return (
    <div className="space-y-6 p-6">
      <div className="animate-fade-in">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Security Overview</h1>
        <AlertsTable />
      </div>
      <div className="animate-fade-in animation-delay-200">
        <h2 className="text-xl font-semibold text-gray-800 dark:text-gray-200 mb-4">Network Analytics</h2>
        <Charts />
      </div>
      <div className="animate-fade-in animation-delay-400">
        <ZeekLogsTable />
      </div>
    </div>
  );
}

function App() {
  const [startTime, setStartTime] = useState(null);

  useEffect(() => {
    onSystemInfo((info) => {
      setStartTime(info.startTime);
    });
  }, []);

  return (
    <Router>
      <ThemeProvider>
        <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 transition-all duration-200">
          <Navbar />
          <main className="max-w-7xl mx-auto pt-20 pb-6 px-4 sm:px-6 lg:px-8">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={
                <div className="p-6">
                  <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Security Alerts</h1>
                  <AlertsTable />
                </div>
              } />
              <Route path="/logs" element={
                <div className="p-6">
                  <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Network Logs</h1>
                  <ZeekLogsTable />
                </div>
              } />
            </Routes>
          </main>
          <Footer startTime={startTime} />
        </div>
        <Toaster 
          position="bottom-right"
          toastOptions={{
            duration: 4000,
            className: 'dark:bg-gray-800 dark:text-white',
            style: {
              background: 'var(--toast-bg)',
              color: 'var(--toast-color)',
            },
          }}
        />
      </ThemeProvider>
    </Router>
  );
}

export default App;
