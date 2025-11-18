import { useEffect, useState } from 'react';

export default function Footer({ startTime }) {
  const [uptime, setUptime] = useState('');

  useEffect(() => {
    const updateUptime = () => {
      if (!startTime) return;

      const start = new Date(startTime);
      const now = new Date();
      const diff = now - start;

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      setUptime(`${hours}h ${minutes}m ${seconds}s`);
    };

    const interval = setInterval(updateUptime, 1000);
    updateUptime();

    return () => clearInterval(interval);
  }, [startTime]);

  return (
    <footer className="bg-white dark:bg-gray-800 shadow-lg mt-8">
      <div className="max-w-7xl mx-auto px-4 py-3">
        <div className="flex justify-between items-center text-sm text-gray-500 dark:text-gray-400">
          <div>
            Last Updated: {new Date().toLocaleString()}
          </div>
          <div>
            System Uptime: {uptime || 'Calculating...'}
          </div>
        </div>
      </div>
    </footer>
  );
}