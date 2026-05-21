/**
 * API客户端
 * 与后端API交互的封装
 */
import axios from 'axios'

const API_BASE_URL = '/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 响应拦截器
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    console.error('API错误:', error)
    return Promise.reject(error)
  }
)

export interface ScanTarget {
  id: number
  url: string
  name: string
  description: string
  created_at: string
  updated_at: string
}

export interface ScanTask {
  id: number
  target_id: number
  target_name: string
  target_url: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  scan_type: string
  started_at: string | null
  completed_at: string | null
  created_at: string
  risk_score: number | null
  risk_level: 'low' | 'medium' | 'high' | 'critical' | null
  vulnerabilities_count: number
}

export interface Vulnerability {
  id: number
  scan_id: number
  vuln_type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  location: string
  cvss_base_score: number
  cvss_temporal_score: number
  cvss_environmental_score: number
  cvss_vector: string
  evidence: string
  recommendation: string
  created_at: string
}

export interface Statistics {
  total_scans: number
  completed_scans: number
  total_vulnerabilities: number
  severity_distribution: { [key: string]: number }
  type_distribution: { [key: string]: number }
}

// API方法
export const scanAPI = {
  // 目标管理
  getTargets: () => api.get<any, { success: boolean; data: ScanTarget[] }>('/scan/targets'),
  
  createTarget: (data: { url: string; name?: string; description?: string }) =>
    api.post<any, { success: boolean; data: ScanTarget }>('/scan/targets', data),
  
  deleteTarget: (id: number) =>
    api.delete<any, { success: boolean; message: string }>(`/scan/targets/${id}`),
  
  // 扫描任务
  startScan: (data: { target_id: number; scan_type?: string }) =>
    api.post<any, { success: boolean; data: ScanTask }>('/scan/start', data),
  
  getTasks: (targetId?: number) => {
    const params = targetId ? { target_id: targetId } : {}
    return api.get<any, { success: boolean; data: ScanTask[] }>('/scan/tasks', { params })
  },
  
  getTask: (id: number) =>
    api.get<any, { success: boolean; data: ScanTask & { target: ScanTarget; vulnerabilities: Vulnerability[] } }>(`/scan/tasks/${id}`),
  
  // 漏洞
  getVulnerabilities: (scanId?: number) => {
    const params = scanId ? { scan_id: scanId } : {}
    return api.get<any, { success: boolean; data: Vulnerability[] }>('/scan/vulnerabilities', { params })
  },
  
  // 统计
  getStatistics: () =>
    api.get<any, { success: boolean; data: Statistics }>('/scan/statistics'),

  // 批量清空任务（默认清空最近5条）
  clearTasks: (params?: { scope?: 'recent' | 'all'; limit?: number; target_id?: number }) =>
    api.delete<any, { success: boolean; deleted: number }>('/scan/tasks/clear', { params }),
}

export default api
