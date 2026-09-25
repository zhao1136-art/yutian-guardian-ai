import React, { useState } from 'react'
import UploadPanel from './components/UploadPanel.jsx'
import MonitorPanel from './components/MonitorPanel.jsx'
import ChatPanel from './components/ChatPanel.jsx'

const VIEWS = [
  { id: 'detect', label: '样本检测' },
  { id: 'monitor', label: '系统监控' },
  { id: 'chat', label: 'AI 对话' },
]

export default function App() {
  const [view, setView] = useState('detect')
  const [lastDetection, setLastDetection] = useState(null)

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