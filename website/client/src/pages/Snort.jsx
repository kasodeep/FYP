import AlertsTable from '../components/AlertsTable'

export default function Snort() {
  return (
    <div className="space-y-8">
      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Snort Alerts</h1>
      <AlertsTable />
    </div>
  )
}