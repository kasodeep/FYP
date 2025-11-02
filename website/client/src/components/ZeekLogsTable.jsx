/* eslint-disable no-unused-vars */
import { useState, useEffect } from 'react'
import { getLatestLogs } from '../utils/api'
import { AnimatePresence, motion } from 'framer-motion'

export default function ZeekLogsTable() {
  const [logs, setLogs] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [selectedTypes, setSelectedTypes] = useState(['conn', 'http', 'dns'])

  const logTypeColors = {
    conn: { bg: 'bg-blue-100 dark:bg-blue-800/30', text: 'text-blue-700 dark:text-blue-300' },
    http: { bg: 'bg-purple-100 dark:bg-purple-800/30', text: 'text-purple-700 dark:text-purple-300' },
    dns: { bg: 'bg-emerald-100 dark:bg-emerald-800/30', text: 'text-emerald-700 dark:text-emerald-300' }
  }

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        setIsLoading(true)
        const response = await getLatestLogs(selectedTypes)
        setLogs(response.logs)
      } catch (error) {
        console.error('Error fetching Zeek logs:', error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchLogs()
    const interval = setInterval(fetchLogs, 15000) // Refresh every 15 seconds

    return () => clearInterval(interval)
  }, [selectedTypes])

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Network Logs</h2>
        <div className="flex items-center gap-2">
          {isLoading && (
            <span className="flex items-center">
              <svg className="animate-spin h-4 w-4 text-blue-500" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            </span>
          )}
          <select
            className="select min-w-[120px]"
            value={selectedTypes.length === 3 ? 'all' : selectedTypes.join(',')}
            onChange={(e) => {
              const value = e.target.value;
              if (value === 'all') {
                setSelectedTypes(['conn', 'http', 'dns']);
              } else {
                setSelectedTypes(value.split(',').filter(Boolean));
              }
            }}
          >
            <option value="all">All Types</option>
            <option value="conn">Connection</option>
            <option value="http">HTTP</option>
            <option value="dns">DNS</option>
            <option value="conn,http">Conn + HTTP</option>
            <option value="conn,dns">Conn + DNS</option>
            <option value="http,dns">HTTP + DNS</option>
          </select>
        </div>
      </div>

      <div className="border rounded-lg dark:border-gray-700 overflow-x-auto">
        <table className="w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider whitespace-nowrap">
                Type
              </th>
              <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider whitespace-nowrap hidden sm:table-cell">
                Time
              </th>
              <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider whitespace-nowrap">
                Source → Dest
              </th>
              <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Event
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            <AnimatePresence initial={false}>
              {logs.map((log, index) => (
                <motion.tr 
                  key={`${log.timestamp}-${index}`}
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                >
                  <td className="px-3 py-2 whitespace-nowrap text-sm">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium
                      ${log.type === 'conn' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' :
                        log.type === 'http' ? 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200' :
                        log.type === 'dns' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200' :
                        'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                      }`}>
                      {log.type.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300 hidden sm:table-cell">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-3 py-2 text-sm text-gray-900 dark:text-gray-300">
                    <span className="font-mono whitespace-nowrap">{log.source}</span>
                    <span className="mx-1 text-gray-400">→</span>
                    <span className="font-mono whitespace-nowrap">{log.destination}</span>
                  </td>
                  <td className="px-3 py-2 text-sm text-gray-900 dark:text-gray-300">
                    <div className="max-w-md truncate">
                      {log.event}
                    </div>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
            {logs.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  No logs found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}