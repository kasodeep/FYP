import io from 'socket.io-client'

const SOCKET_URL = 'http://localhost:5000';

export const socket = io(SOCKET_URL, {
  autoConnect: true,
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
});

let systemInfo = null;
let systemInfoListeners = [];

export const onSystemInfo = (callback) => {
  systemInfoListeners.push(callback);
  if (systemInfo) {
    callback(systemInfo);
  }
};

socket.on('connect', () => {
  console.log('Socket connected');
});

socket.on('disconnect', () => {
  console.log('Socket disconnected');
});

socket.on('connect_error', (error) => {
  console.error('Socket connection error:', error);
});

socket.on('error', (error) => {
  console.error('Socket error:', error);
});

socket.on('systemInfo', (info) => {
  systemInfo = info;
  systemInfoListeners.forEach(listener => listener(info));
});