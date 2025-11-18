/* eslint-disable no-unused-vars */
import { useState, useEffect } from 'react'
import { socket } from '../utils/socket'
import { getLatestAlerts } from '../utils/api'
import { AnimatePresence, motion } from 'framer-motion'
import toast from 'react-hot-toast'

const getSeverityIcon = (severity) => {
  switch (severity) {
    case 'high':
      return '🔴';
    case 'medium':
      return '🟡';
    case 'low':
      return '🟢';
    default:
      return '⚪';
  }
};

export default function AlertsTable() {
  const [alerts, setAlerts] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);
  const alertsPerPage = 10;

  useEffect(() => {
    // Initial load of alerts
    const fetchAlerts = async () => {
      try {
        console.log('Fetching initial alerts...');
        const { alerts: initialAlerts } = await getLatestAlerts();
        console.log('Initial alerts received:', initialAlerts);
        setAlerts(initialAlerts || []);
      } catch (error) {
        console.error('Error fetching alerts:', error);
      }
    };
    fetchAlerts();

    // Connect to WebSocket for real-time updates
    const handleNewAlert = (alert) => {
      console.log('New alert received:', alert);
      if (!isPaused) {
        setAlerts((prev) => {
          const newAlerts = [alert, ...prev.slice(0, 49)];
          console.log('Updated alerts:', newAlerts);
          return newAlerts;
        });

        // Show toast notification
        const icon = getSeverityIcon(alert.severity);
        toast(
          <div className="flex items-start">
            <div className="flex-1">
              <p className="font-medium">{`${icon} ${alert.message}`}</p>
              <p className="text-sm text-gray-500">
                {`${alert.sourceIp} → ${alert.destinationIp} (${alert.protocol})`}
              </p>
            </div>
          </div>,
          {
            duration: alert.severity === 'high' ? 6000 : 4000,
            position: 'top-right',
            className: `${
              alert.severity === 'high' 
                ? 'border-l-4 border-scarlet' 
                : alert.severity === 'medium'
                ? 'border-l-4 border-gold'
                : 'border-l-4 border-emerald'
            }`,
          }
        );
      }
    };

    console.log('Setting up socket listener for newAlert');
    socket.on('newAlert', handleNewAlert);

    return () => {
      console.log('Cleaning up socket listener');
      socket.off('newAlert', handleNewAlert);
    };
  }, [isPaused]);

  // Filter alerts based on severity and search term
  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
    const matchesSearch = searchTerm === '' || 
      alert.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.sourceIp.includes(searchTerm) ||
      alert.destinationIp.includes(searchTerm);
    return matchesSeverity && matchesSearch;
  });

  // Calculate pagination
  const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
  const paginatedAlerts = filteredAlerts.slice(
    (page - 1) * alertsPerPage,
    page * alertsPerPage
  );

  return (
    <div className="card">
      <div className="flex flex-col space-y-4">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Real-Time Snort Alerts</h2>
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`btn ${
              isPaused 
                ? 'bg-emerald hover:bg-emerald/90' 
                : 'bg-scarlet hover:bg-scarlet/90'
            } text-white w-full sm:w-auto`}
          >
            {isPaused ? 'Resume' : 'Pause'}
          </button>
        </div>

        <div className="flex flex-col md:flex-row gap-4">
          {/* Search bar */}
          <div className="flex-1">
            <div className="relative">
              <input
                type="text"
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-lg border dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
              />
              <svg
                className="absolute left-3 top-2.5 h-5 w-5 text-gray-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
            </div>
          </div>

          {/* Severity filter dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full md:w-48 px-4 py-2 rounded-lg border dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div className="mt-6 overflow-x-auto rounded-lg border dark:border-gray-700">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Timestamp
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Source IP
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden md:table-cell">
                Destination IP
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden sm:table-cell">
                Protocol
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Message
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Severity
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            <AnimatePresence initial={false}>
              {paginatedAlerts.map((alert, index) => (
                <motion.tr 
                  key={`${alert.timestamp}-${index}`}
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                >
                  <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">
                    {alert.sourceIp}
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300 hidden md:table-cell">
                    {alert.destinationIp}
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300 hidden sm:table-cell">
                    {alert.protocol}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-900 dark:text-gray-300">
                    <div className="max-w-md truncate">
                      {alert.message}
                    </div>
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap text-sm">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize
                      ${alert.severity === 'high' 
                        ? 'bg-red-100 text-red-600 dark:bg-red-900/50 dark:text-red-300' 
                        : alert.severity === 'medium'
                        ? 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/50 dark:text-yellow-300'
                        : 'bg-green-100 text-green-600 dark:bg-green-900/50 dark:text-green-300'
                      }`}>
                      {getSeverityIcon(alert.severity)} {alert.severity}
                    </span>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
            {paginatedAlerts.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  No alerts found
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-900 border-t dark:border-gray-700">
          <div className="flex-1 flex justify-between sm:hidden">
            <button
              onClick={() => setPage(prev => Math.max(1, prev - 1))}
              disabled={page === 1}
              className="btn btn-secondary"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(prev => Math.min(totalPages, prev + 1))}
              disabled={page === totalPages}
              className="btn btn-secondary"
            >
              Next
            </button>
          </div>
          <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                Showing{' '}
                <span className="font-medium">{(page - 1) * alertsPerPage + 1}</span>
                {' '}-{' '}
                <span className="font-medium">
                  {Math.min(page * alertsPerPage, filteredAlerts.length)}
                </span>
                {' '}of{' '}
                <span className="font-medium">{filteredAlerts.length}</span>
                {' '}results
              </p>
            </div>
            <div>
              <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                <button
                  onClick={() => setPage(1)}
                  disabled={page === 1}
                  className="btn-pagination rounded-l-md"
                >
                  First
                </button>
                <button
                  onClick={() => setPage(prev => Math.max(1, prev - 1))}
                  disabled={page === 1}
                  className="btn-pagination"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={page === totalPages}
                  className="btn-pagination"
                >
                  Next
                </button>
                <button
                  onClick={() => setPage(totalPages)}
                  disabled={page === totalPages}
                  className="btn-pagination rounded-r-md"
                >
                  Last
                </button>
              </nav>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}