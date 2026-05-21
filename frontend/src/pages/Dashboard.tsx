import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { scanAPI, Statistics, ScanTask } from '@/lib/api'
import { Activity, AlertTriangle, Shield, TrendingUp } from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts'

export default function Dashboard() {
  const [stats, setStats] = useState<Statistics | null>(null)
  const [recentScans, setRecentScans] = useState<ScanTask[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      setLoading(true)
      const [statsRes, scansRes] = await Promise.all([
        scanAPI.getStatistics(),
        scanAPI.getTasks(),
      ])
      setStats(statsRes.data)
      setRecentScans(scansRes.data.slice(0, 5))
    } catch (error) {
      console.error('加载数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const severityColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
  }

  const severityData = stats
    ? Object.entries(stats.severity_distribution).map(([name, value]) => ({
        name: name === 'critical' ? '严重' : name === 'high' ? '高' : name === 'medium' ? '中' : '低',
        value,
        color: severityColors[name as keyof typeof severityColors] || '#6b7280',
      }))
    : []

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">加载中...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* 统计卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="总扫描次数"
          value={stats?.total_scans || 0}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="已完成扫描"
          value={stats?.completed_scans || 0}
          icon={Shield}
          color="green"
        />
        <StatCard
          title="发现漏洞"
          value={stats?.total_vulnerabilities || 0}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="扫描成功率"
          value={
            stats?.total_scans
              ? `${Math.round((stats.completed_scans / stats.total_scans) * 100)}%`
              : '0%'
          }
          icon={TrendingUp}
          color="purple"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 漏洞严重程度分布 */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">漏洞严重程度分布</h2>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-400">
              暂无数据
            </div>
          )}
        </div>

        {/* 最近扫描 */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">最近扫描</h2>
            <button
              className="text-sm px-3 py-1 rounded border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              onClick={async () => {
                const ok = window.confirm('确认清空最近5条扫描记录？此操作不可恢复。')
                if (!ok) return
                try {
                  await scanAPI.clearTasks({ scope: 'recent', limit: 5 })
                  await loadData()
                } catch (e) {
                  console.error('清空失败', e)
                  alert('清空失败，请稍后重试')
                }
              }}
              disabled={recentScans.length === 0}
            >
              清空
            </button>
          </div>
          <div className="space-y-3">
            {recentScans.length > 0 ? (
              recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/results/${scan.id}`}
                  className="block p-3 border rounded-lg hover:bg-gray-50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-medium">
                          {scan.target_name || scan.target_url || `扫描 #${scan.id}`}
                        </span>
                        <StatusBadge status={scan.status} />
                      </div>
                      <div className="text-sm text-gray-500 mt-1">
                        {new Date(scan.created_at).toLocaleString('zh-CN')}
                      </div>
                    </div>
                    {scan.risk_level && (
                      <RiskBadge level={scan.risk_level} />
                    )}
                  </div>
                </Link>
              ))
            ) : (
              <div className="text-center text-gray-400 py-8">暂无扫描记录</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, color }: any) {
  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    red: 'bg-red-500',
    purple: 'bg-purple-500',
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
        </div>
        <div className={`${colorClasses[color as keyof typeof colorClasses]} p-3 rounded-lg`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const statusConfig = {
    pending: { label: '等待中', class: 'bg-gray-100 text-gray-700' },
    running: { label: '运行中', class: 'bg-blue-100 text-blue-700' },
    completed: { label: '已完成', class: 'bg-green-100 text-green-700' },
    failed: { label: '失败', class: 'bg-red-100 text-red-700' },
  }

  const config = statusConfig[status as keyof typeof statusConfig] || statusConfig.pending

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${config.class}`}>
      {config.label}
    </span>
  )
}

function RiskBadge({ level }: { level: string }) {
  const riskConfig = {
    low: { label: '低', class: 'bg-green-100 text-green-700' },
    medium: { label: '中', class: 'bg-yellow-100 text-yellow-700' },
    high: { label: '高', class: 'bg-orange-100 text-orange-700' },
    critical: { label: '严重', class: 'bg-red-100 text-red-700' },
  }

  const config = riskConfig[level as keyof typeof riskConfig] || riskConfig.low

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${config.class}`}>
      {config.label}
    </span>
  )
}
