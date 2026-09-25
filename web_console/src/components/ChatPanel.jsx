import React, { useState } from 'react'
import { explain } from '../api.js'

// 四个固定维度按钮：点击即显示对应结论/答案，无需自由输入
const BUTTONS = [
  { label: '结论摘要', q: '结论是什么' },
  { label: '判定依据', q: '有哪些依据' },
  { label: '处置建议', q: '我该怎么办' },
  { label: '风险程度', q: '风险高吗' },
]

export default function ChatPanel({ lastDetection, onOpenDetect }) {
  const [answers, setAnswers] = useState([]) // {q, reply, matches}
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const ask = async (q) => {
    if (busy) return
    setErr('')
    setBusy(true)
    try {
      const r = await explain(q, lastDetection || null)
      setAnswers((a) => [...a, {
        q,
        reply: r.reply || '',
        matches: r.top_matches || (r.analysis && r.analysis.top_matches) || [],
      }])
    } catch (e) {
      setErr(e.message || '解释引擎请求失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel chat">
      <div className="panel-head">
        <h2>AI 对话 <span className="sub">（点击按钮查看对应结论，自研本地引擎）</span></h2>
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
            尚未有检测上下文，请先上传样本检测。
            <button className="ghost small" onClick={onOpenDetect}>去检测</button>
          </>
        )}
      </div>

      <div className="quick-row">
        {BUTTONS.map((b) => (
          <button key={b.q} className="ghost small" onClick={() => ask(b.q)} disabled={busy}>
            {b.label}
          </button>
        ))}
      </div>

      <div className="msg-list">
        {answers.length === 0 && (
          <p className="hint center">上传样本完成检测后，点击上方按钮查看结论摘要 / 判定依据 / 处置建议 / 风险程度。</p>
        )}
        {answers.map((a, i) => (
          <div key={i} className="msg ai">
            <div className="bubble">
              <div className="answer-q">{a.q}</div>
              <div>{a.reply}</div>
              {a.matches.length > 0 && (
                <div className="answer-matches">
                  <span className="am-title">相似样本依据：</span>
                  {a.matches.slice(0, 4).map((m, j) => (
                    <span className="match-chip" key={j}
                      style={{ background: m.label_name === '恶意' ? '#e5484d' : '#30a46c' }}>
                      {m.label_name} {Math.round(m.score * 100)}%
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {busy && <div className="msg ai"><div className="bubble typing">正在分析…</div></div>}
      </div>

      {err && <p className="error">{err}</p>}
    </section>
  )
}
