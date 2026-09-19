import React, { useState } from 'react'
import { explain } from '../api.js'

const QUICK = ['为什么这么判定', '有哪些依据', '我该怎么办', '风险高吗']

export default function ChatPanel({ lastDetection, onOpenDetect }) {
  const [msgs, setMsgs] = useState([]) // {role:'user'|'ai', text, planBytes}
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const send = async (raw) => {
    const q = (raw ?? input).trim()
    if (!q || busy) return
    setInput(''); setErr('')
    setMsgs((m) => [...m, { role: 'user', text: q }])
    setBusy(true)
    try {
      const det = lastDetection || null
      const r = await explain(q, det)
      setMsgs((m) => [...m, { role: 'ai', text: r.reply || '' }])
    } catch (e) {
      setErr(e.message || '解释引擎请求失败')
    } finally {
      setBusy(false)
    }
  }

  const onKey = (e) => { if (e.key === 'Enter' && !e.shiftKey) send() }

  return (
    <section className="panel chat">
      <div className="panel-head">
        <h2>AI 对话 <span className="sub">（自研本地解释引擎，离线）</span></h2>
      </div>

      <div className="ctx-bar">
        {lastDetection ? (
          <>
            <span className="dot ok" />
            正在引用最近一次检测：<b>{lastDetection.fused_state}</b>（{lastDetection.label ?? '-'}）
            <button className="ghost small" onClick={onOpenDetect}>去重新检测</button>
          </>
        ) : (
          <>
            <span className="dot" />
            尚未有检测上下文，可直接提问或先上传样本。
            <button className="ghost small" onClick={onOpenDetect}>去检测</button>
          </>
        )}
      </div>

      <div className="msg-list">
        {msgs.length === 0 && (
          <p className="hint center">基于最近一次检测结果，点击下方问题或输入文本，我会给出解释与建议。</p>
        )}
        {msgs.map((m, i) => (
          <div key={i} className={`msg ${m.role}`}>
            <div className="bubble">{m.text}</div>
          </div>
        ))}
        {busy && <div className="msg ai"><div className="bubble typing">正在分析…</div></div>}
      </div>

      <div className="quick-row">
        {QUICK.map((q) => (
          <button key={q} className="ghost small" onClick={() => send(q)} disabled={busy}>
            {q}
          </button>
        ))}
      </div>

      {err && <p className="error">{err}</p>}

      <textarea
        className="chat-input"
        placeholder="输入问题（如：这个结论可靠吗？）"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={onKey}
        rows={2}
      />
      <button className="primary" onClick={() => send()} disabled={busy}>
        {busy ? '分析中…' : '发送'}
      </button>
    </section>
  )
}