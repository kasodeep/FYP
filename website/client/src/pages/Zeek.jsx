import ZeekLogsTable from '../components/ZeekLogsTable'

export default function Zeek() {
  return (
    <div className="space-y-8">
      <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Zeek Logs</h1>
      <ZeekLogsTable />
    </div>
  )
}