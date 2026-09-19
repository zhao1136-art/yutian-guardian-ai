import React, { useEffect, useState, useCallback } from 'react'
import { fetchHealth, getToken, setToken } from './api.js'
import UploadPanel from './components/UploadPanel.jsx'
import MonitorPanel from './components/MonitorPanel.jsx'
import ChatPanel from './components/ChatPanel.jsx'

const VIEWS = [
  { id: 'detect', label: '样本检测' },
  { id: 'monitor', label: '系统监控' },
  { id: 'chat', label: 'AI 对话' },
]

export default function App() {
  const [token, setTokenState] = useState(getToken())
  const [health, setHealth] = useState(null)
  const [view, setView] = useState('detect')
  const [lastDetection, setLastDetection] = useState(null)

  const refreshHealth = useCallback(async () => {
    try {
      const h = await fetchHealth()
      setHealth(h)
    } catch (e) {
      setHealth({ status: 'offline', error: e.message })
    }
  }, [])

  useEffect(() => { refreshHealth() }, [refreshHealth])

  const onToken = (v) => { setToken(v); setTokenState(v) }

  const onDetected = (detection) => {
    setLastDetection(detection)
    setView('detect')
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-dot" />
          <h1>御天防护型 AI</h1>
          <span className="sub">Guardian AI · 四态融合判定</span>
        </div>
        <div className="status-row">
          <span className={`pill ${health && health.status === 'ok' ? 'ok' : 'bad'}`}>
            {health && health.status === 'ok' ? '模型就绪' : (health ? '服务离线' : '连接中…')}
          </span>
          <input
            className="token-input"
            placeholder="Bearer token（monitor_data/api_token.txt）"
            value={token}
            onChange={(e) => onToken(e.target.value)}
          />
        </div>
      </header>

      <nav className="tabs">
        {VIEWS.map((v) => (
          <button
            key={v.id}
            className={`tab ${view === v.id ? 'active' : ''}`}
            onClick={() => setView(v.id)}
          >
            {v.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {view === 'detect' && (
          <UploadPanel lastDetection={lastDetection} onDetected={onDetected} />
        )}
        {view === 'monitor' && <MonitorPanel />}
        {view === 'chat' && (
          <ChatPanel lastDetection={lastDetection} onOpenDetect={() => setView('detect')} />
        )}
      </main>
    </div>
  )
}