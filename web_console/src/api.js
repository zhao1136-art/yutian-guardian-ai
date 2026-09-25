// 与后端 API 交互的统一封装
// token 存 localStorage，所有请求带 Authorization: Bearer

const BASE = '' // 生产同源；dev 由 vite 代理

export function getToken() {
  return localStorage.getItem('guardian_token') || ''
}

export function setToken(t) {
  localStorage.setItem('guardian_token', (t || '').trim())
}

function authHeaders(extra = {}) {
  const h = { ...extra }
  const t = getToken()
  if (t) h['Authorization'] = `Bearer ${t}`
  return h
}

export async function fetchJSON(path, options = {}) {
  const res = await fetch(BASE + path, options)
  const ct = res.headers.get('content-type') || ''
  const data = ct.includes('json') ? await res.json() : null
  if (!res.ok) {
    const msg = (data && (data.error || data.code)) || `HTTP ${res.status}`
    throw new Error(String(msg))
  }
  return data
}

// 健康检查（无需 token）
export function fetchHealth() {
  return fetchJSON('/health')
}

// 上传文件做融合判定
export async function predictFile(file) {
  const form = new FormData()
  form.append('file', file)
  return fetchJSON('/predict', {
    method: 'POST',
    headers: authHeaders(), // 不手动设 Content-Type，浏览器会带 boundary
    body: form,
  })
}

// 拉取监控结果
export function fetchMonitor() {
  return fetchJSON('/monitor', { headers: authHeaders() })
}

// 自研本地解释引擎：生成结论/依据/建议，或回答追问
export async function explain(message, detectionContext, history) {
  const body = {}
  if (message) body.message = message
  if (detectionContext) body.detection_context = detectionContext
  if (Array.isArray(history) && history.length) body.chat_history = history
  return fetchJSON('/explain', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  })
}