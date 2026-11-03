import { useEffect, useState } from 'react'
import { scanAPI, ScanTarget } from '@/lib/api'
import { Plus, Trash2, Play, ExternalLink } from 'lucide-react'

export default function Targets() {
  const [targets, setTargets] = useState<ScanTarget[]>([])
  const [showAddModal, setShowAddModal] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadTargets()
  }, [])

  const loadTargets = async () => {
    try {
      setLoading(true)
      const res = await scanAPI.getTargets()
      setTargets(res.data)
    } catch (error) {
      console.error('加载目标失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('确定要删除此目标吗？')) return

    try {
      await scanAPI.deleteTarget(id)
      setTargets(targets.filter((t) => t.id !== id))
    } catch (error) {
      console.error('删除失败:', error)
      alert('删除失败，请重试')
    }
  }

  const handleStartScan = async (targetId: number) => {
    try {
      await scanAPI.startScan({ target_id: targetId, scan_type: 'all' })
      alert('扫描任务已启动！')
    } catch (error) {
      console.error('启动扫描失败:', error)
      alert('启动扫描失败，请重试')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">扫描目标管理</h1>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
        >
          <Plus className="h-4 w-4" />
          <span>添加目标</span>
        </button>
      </div>

      {/* Targets List */}
      {loading ? (
        <div className="text-center py-12 text-gray-500">加载中...</div>
      ) : targets.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-gray-500 mb-4">还没有添加任何扫描目标</p>
          <button
            onClick={() => setShowAddModal(true)}
            className="text-primary hover:underline"
          >
            点击添加第一个目标
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {targets.map((target) => (
            <TargetCard
              key={target.id}
              target={target}
              onDelete={() => handleDelete(target.id)}
              onScan={() => handleStartScan(target.id)}
            />
          ))}
        </div>
      )}

      {/* Add Target Modal */}
      {showAddModal && (
        <AddTargetModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false)
            loadTargets()
          }}
        />
      )}
    </div>
  )
}

function TargetCard({
  target,
  onDelete,
  onScan,
}: {
  target: ScanTarget
  onDelete: () => void
  onScan: () => void
}) {
  return (
    <div className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className="font-semibold text-lg mb-1">
            {target.name || '未命名目标'}
          </h3>
          <a
            href={target.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-primary hover:underline flex items-center space-x-1"
          >
            <span className="truncate">{target.url}</span>
            <ExternalLink className="h-3 w-3 flex-shrink-0" />
          </a>
        </div>
      </div>

      {target.description && (
        <p className="text-sm text-gray-600 mb-4">{target.description}</p>
      )}

      <div className="flex items-center justify-between pt-4 border-t">
        <button
          onClick={onScan}
          className="flex items-center space-x-2 px-3 py-1.5 bg-green-500 text-white rounded hover:bg-green-600 transition-colors text-sm"
        >
          <Play className="h-4 w-4" />
          <span>开始扫描</span>
        </button>

        <button
          onClick={onDelete}
          className="p-1.5 text-red-500 hover:bg-red-50 rounded transition-colors"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

function AddTargetModal({
  onClose,
  onSuccess,
}: {
  onClose: () => void
  onSuccess: () => void
}) {
  const [formData, setFormData] = useState({
    url: '',
    name: '',
    description: '',
  })
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.url) {
      alert('请输入目标URL')
      return
    }

    try {
      setSubmitting(true)
      await scanAPI.createTarget(formData)
      onSuccess()
    } catch (error) {
      console.error('添加目标失败:', error)
      alert('添加目标失败，请重试')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
        <div className="px-6 py-4 border-b">
          <h2 className="text-xl font-semibold">添加扫描目标</h2>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              目标URL <span className="text-red-500">*</span>
            </label>
            <input
              type="url"
              value={formData.url}
              onChange={(e) => setFormData({ ...formData, url: e.target.value })}
              placeholder="https://example.com"
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              目标名称
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="我的网站"
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              描述
            </label>
            <textarea
              value={formData.description}
              onChange={(e) =>
                setFormData({ ...formData, description: e.target.value })
              }
              placeholder="目标描述..."
              rows={3}
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>

          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border rounded-lg hover:bg-gray-50 transition-colors"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {submitting ? '添加中...' : '添加'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
