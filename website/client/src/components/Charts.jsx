import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { getAlertsBySeverity, getAlertsTrend, getProtocolsDistribution } from '../utils/api';
import { socket } from '../utils/socket';

const SEVERITY_COLORS = {
  high: '#DC2626',    // Red
  medium: '#FACC15',  // Yellow
  low: '#10B981'      // Green
};

const PROTOCOL_COLORS = {
  TCP: '#3B82F6',     // Blue
  UDP: '#8B5CF6',     // Purple
  ICMP: '#EC4899',    // Pink
  default: '#6B7280'  // Gray
};

export default function Charts() {
  const [severityData, setSeverityData] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [protocolData, setProtocolData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [severity, trend, protocols] = await Promise.all([
          getAlertsBySeverity(),
          getAlertsTrend(),
          getProtocolsDistribution()
        ]);

        setSeverityData(severity.data);
        setTrendData(trend.data);
        setProtocolData(protocols.data);
      } catch (error) {
        console.error('Error fetching chart data:', error);
      } finally {
        setLoading(false);
      }
    };

    // Initial fetch
    fetchData();

    // Socket event handlers for real-time updates
    const handleNewAlert = async () => {
      // Fetch updated data when new alert arrives
      fetchData();
    };

    socket.on('newAlert', handleNewAlert);

    // Fallback polling every 30 seconds
    const interval = setInterval(fetchData, 30000);

    return () => {
      clearInterval(interval);
      socket.off('newAlert', handleNewAlert);
    };
  }, []);

  if (loading) {
    return <div className="text-center">Loading charts...</div>;
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Severity Distribution */}
      <div className="card overflow-hidden">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Alerts by Severity
        </h3>
        <div className="min-h-[300px]">
          <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={severityData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {severityData.map((entry) => (
                <Cell key={`cell-${entry.name}`} fill={SEVERITY_COLORS[entry.name]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
      </div>

      {/* Alerts Trend */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Alerts Trend (24h)
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart
            data={trendData}
            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="count" stroke="#3B82F6" activeDot={{ r: 8 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Protocols Distribution */}
      <div className="card lg:col-span-2">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Protocol Distribution
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart
            data={protocolData}
            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar 
              dataKey="value" 
              fill="#38BDF8"
              name="Count"
            >
              {protocolData.map((entry) => (
                <Cell 
                  key={`cell-${entry.name}`} 
                  fill={PROTOCOL_COLORS[entry.name] || PROTOCOL_COLORS.default} 
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}