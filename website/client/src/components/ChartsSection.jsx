import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell
} from 'recharts'

export default function ChartsSection() {
  const [severityData, setSeverityData] = useState([])
  const [protocolData, setProtocolData] = useState([])
  const [trendData, setTrendData] = useState([])

  useEffect(() => {
    const fetchChartData = async () => {
      try {
        const [severityRes, protocolRes, trendRes] = await Promise.all([
          axios.get('http://localhost:5000/api/charts/alerts-severity'),
          axios.get('http://localhost:5000/api/charts/protocols'),
          axios.get('http://localhost:5000/api/charts/alerts-trend')
        ])

        setSeverityData(severityRes.data.data)
        setProtocolData(protocolRes.data.data)
        setTrendData(trendRes.data.data)
      } catch (error) {
        console.error('Error fetching chart data:', error)
      }
    }

    fetchChartData()
    const interval = setInterval(fetchChartData, 60000) // Refresh every minute

    return () => clearInterval(interval)
  }, [])

  const COLORS = ['#DC2626', '#FACC15', '#10B981']

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Analytics Overview</h2>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alerts by Severity */}
        <div className="bg-white/50 dark:bg-gray-800/50 rounded-lg p-4">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Alerts by Severity</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityData}>
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#3B82F6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-white/50 dark:bg-gray-800/50 rounded-lg p-4">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Protocol Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={protocolData}
                cx="50%"
                cy="50%"
                innerRadius={40}
                outerRadius={60}
                fill="#8884d8"
                paddingAngle={5}
                dataKey="value"
              >
                {protocolData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Alerts Trend */}
        <div className="bg-white/50 dark:bg-gray-800/50 rounded-lg p-4">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Alerts Trend (24h)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trendData}>
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="count" stroke="#3B82F6" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}