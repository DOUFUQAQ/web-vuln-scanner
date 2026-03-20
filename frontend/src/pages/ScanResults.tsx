import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { scanAPI, Vulnerability } from '@/lib/api'
import { ArrowLeft, AlertCircle, Info, CheckCircle } from 'lucide-react'

export default function ScanResults() {
  const { taskId } = useParams<{ taskId: string }>()
  const navigate = useNavigate()
  const [task, setTask] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (taskId) {
      loadTaskDetails(parseInt(taskId))
    }
  }, [taskId])

  const loadTaskDetails = async (id: number) => {
    try {
      setLoading(true)
      const res = await scanAPI.getTask(id)
      setTask(res.data)
    } catch (error) {
      console.error('加载任务详情失败:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">加载中...</div>
      </div>
    )
  }

  if (!task) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500 mb-4">任务不存在</p>
        <button
          onClick={() => navigate('/dashboard')}
          className="text-primary hover:underline"
        >
          返回仪表板
        </button>
      </div>
    )
  }

  const vulnerabilities: Vulnerability[] = task.vulnerabilities || []
  const vulnBySeverity = {
    critical: vulnerabilities.filter((v) => v.severity === 'critical'),
    high: vulnerabilities.filter((v) => v.severity === 'high'),
    medium: vulnerabilities.filter((v) => v.severity === 'medium'),
    low: vulnerabilities.filter((v) => v.severity === 'low'),
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <button
          onClick={() => navigate('/dashboard')}
          className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold">扫描结果详情</h1>
          <p className="text-sm text-gray-500">任务 #{task.id}</p>
        </div>
      </div>

      {/* Task Info */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-gray-600">目标URL</p>
            <p className="font-medium">{task.target?.url || '未知'}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">扫描状态</p>
            <StatusBadge status={task.status} />
          </div>
          <div>
            <p className="text-sm text-gray-600">风险等级</p>
            {task.risk_level && <RiskBadge level={task.risk_level} />}
          </div>
          <div>
            <p className="text-sm text-gray-600">CVSS评分</p>
            <p className="font-medium text-lg">{task.risk_score || 'N/A'}</p>
          </div>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          title="严重"
          count={vulnBySeverity.critical.length}
          color="red"
        />
        <StatCard
          title="高危"
          count={vulnBySeverity.high.length}
          color="orange"
        />
        <StatCard
          title="中危"
          count={vulnBySeverity.medium.length}
          color="yellow"
        />
        <StatCard
          title="低危"
          count={vulnBySeverity.low.length}
          color="green"
        />
      </div>

      {/* Vulnerabilities List */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">发现的漏洞</h2>
        {vulnerabilities.length === 0 ? (
          <div className="bg-white rounded-lg shadow p-12 text-center">
            <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
            <p className="text-lg font-medium text-gray-900 mb-2">
              未发现安全漏洞
            </p>
            <p className="text-gray-500">目标网站看起来很安全！</p>
          </div>
        ) : (
          vulnerabilities.map((vuln) => (
            <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
          ))
        )}
      </div>
    </div>
  )
}

function StatCard({ title, count, color }: any) {
  const colorClasses = {
    red: 'bg-red-100 text-red-700',
    orange: 'bg-orange-100 text-orange-700',
    yellow: 'bg-yellow-100 text-yellow-700',
    green: 'bg-green-100 text-green-700',
  }

  return (
    <div className="bg-white rounded-lg shadow p-4">
      <p className="text-sm text-gray-600">{title}</p>
      <p className={`text-3xl font-bold ${colorClasses[color as keyof typeof colorClasses]}`}>
        {count}
      </p>
    </div>
  )
}

function VulnerabilityCard({ vulnerability }: { vulnerability: Vulnerability }) {
  const [expanded, setExpanded] = useState(false)

  const severityConfig = {
    critical: { icon: AlertCircle, class: 'border-red-500 bg-red-50', badge: 'bg-red-100 text-red-700' },
    high: { icon: AlertCircle, class: 'border-orange-500 bg-orange-50', badge: 'bg-orange-100 text-orange-700' },
    medium: { icon: Info, class: 'border-yellow-500 bg-yellow-50', badge: 'bg-yellow-100 text-yellow-700' },
    low: { icon: Info, class: 'border-green-500 bg-green-50', badge: 'bg-green-100 text-green-700' },
  }

  const config = severityConfig[vulnerability.severity] || severityConfig.low
  const Icon = config.icon

  return (
    <div className={`border-l-4 ${config.class} rounded-lg shadow p-6`}>
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-start space-x-3">
          <Icon className="h-6 w-6 mt-1" />
          <div>
            <h3 className="font-semibold text-lg">{vulnerability.title}</h3>
            <p className="text-sm text-gray-600 mt-1">{vulnerability.description}</p>
          </div>
        </div>
        <span className={`px-3 py-1 text-xs font-medium rounded ${config.badge}`}>
          {vulnerability.severity === 'critical' ? '严重' :
           vulnerability.severity === 'high' ? '高危' :
           vulnerability.severity === 'medium' ? '中危' : '低危'}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <p className="text-sm font-medium text-gray-700">漏洞类型</p>
          <p className="text-sm text-gray-600">{vulnerability.vuln_type}</p>
        </div>
        <div>
          <p className="text-sm font-medium text-gray-700">漏洞位置</p>
          <p className="text-sm text-gray-600 break-all">{vulnerability.location}</p>
        </div>
        <div>
          <p className="text-sm font-medium text-gray-700">CVSS基本评分</p>
          <p className="text-sm text-gray-600">{vulnerability.cvss_base_score}</p>
        </div>
        <div>
          <p className="text-sm font-medium text-gray-700">CVSS向量</p>
          <p className="text-sm text-gray-600 font-mono">{vulnerability.cvss_vector}</p>
        </div>
      </div>

      <button
        onClick={() => setExpanded(!expanded)}
        className="text-primary text-sm font-medium hover:underline"
      >
        {expanded ? '收起详情' : '查看详情'}
      </button>

      {expanded && (
        <div className="mt-4 space-y-4 pt-4 border-t">
          {vulnerability.evidence && (
            <div>
              <p className="text-sm font-medium text-gray-700 mb-1">漏洞证据</p>
              <pre className="text-sm text-gray-600 bg-white p-3 rounded border overflow-x-auto">
                {vulnerability.evidence}
              </pre>
            </div>
          )}
          {vulnerability.recommendation && (
            <div>
              <p className="text-sm font-medium text-gray-700 mb-1">修复建议</p>
              <div className="text-sm text-gray-600 bg-white p-3 rounded border whitespace-pre-line">
                {vulnerability.recommendation}
              </div>
            </div>
          )}
        </div>
      )}
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
    <span className={`inline-block px-2 py-1 text-sm font-medium rounded ${config.class}`}>
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
    <span className={`inline-block px-2 py-1 text-sm font-medium rounded ${config.class}`}>
      {config.label}
    </span>
  )
}
