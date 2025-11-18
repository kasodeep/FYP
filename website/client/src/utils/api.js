import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

// Snort Alerts
export const getLatestAlerts = async () => {
  const response = await axios.get(`${API_BASE_URL}/snort/alerts/latest`);
  return response.data;
};

export const getAlertStats = async () => {
  const response = await axios.get(`${API_BASE_URL}/snort/stats`);
  return response.data;
};

// Zeek Logs
export const getLatestLogs = async (types = []) => {
  console.log('Fetching logs with types:', types);
  const response = await axios.get(`${API_BASE_URL}/zeek/logs/latest`, {
    params: { types: types.join(',') }
  });
  console.log('API response:', response.data);
  return response.data;
};

export const getLogStats = async () => {
  const response = await axios.get(`${API_BASE_URL}/zeek/stats`);
  return response.data;
};

// Charts Data
export const getAlertsBySeverity = async () => {
  const response = await axios.get(`${API_BASE_URL}/charts/alerts-severity`);
  return response.data;
};

export const getAlertsTrend = async () => {
  const response = await axios.get(`${API_BASE_URL}/charts/alerts-trend`);
  return response.data;
};

export const getProtocolsDistribution = async () => {
  const response = await axios.get(`${API_BASE_URL}/charts/protocols`);
  return response.data;
};