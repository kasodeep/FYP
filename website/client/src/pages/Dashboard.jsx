// import { useState, useEffect } from 'react'
import AlertsTable from '../components/AlertsTable'
import ZeekLogsTable from '../components/ZeekLogsTable'
import ChartsSection from '../components/ChartsSection'

export default function Dashboard() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Dashboard Overview</h1>
        <div className="text-sm text-gray-500 dark:text-gray-400">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>
      
      {/* Main content */}
      <div className="grid grid-cols-1 gap-6">
        {/* Analytics Charts Section */}
        <ChartsSection />

        {/* Tables Section */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Real-time Snort Alerts - Takes up 2/3 of the width on xl screens */}
          <div className="xl:col-span-2">
            <AlertsTable />
          </div>

          {/* Latest Zeek Logs - Takes up 1/3 of the width on xl screens */}
          <div className="xl:col-span-1">
            <ZeekLogsTable />
          </div>
        </div>
      </div>
    </div>
  )
}