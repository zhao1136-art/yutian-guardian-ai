import React from 'react'

// 四态 → 展示配色/文案
const STATE_STYLE = {
  恶意: { cls: 'state-mal', icon: '∑' },
  可疑待审: { cls: 'state-susp', icon: '!' },
  良性: { cls: 'state-benign', icon: '✓' },
  未知: { cls: 'state-unknown', icon: '?' },
}

export default function ResultCard({ detection }) {
  if (!detection) return null
  const state = detection.fused_state || detection.label || '未知'
  const st = STATE_STYLE[state] || STATE_STYLE['未知']
  const probs = detection.probabilities || {}

  return (
    <section className="card result">
      <div className={`state-badge ${st.cls}`}>
        <span className="state-icon">{st.icon}</span>
        <div>
          <div className="state-label">{state}</div>
          <div className="state-sub">融合判定</div>
        </div>
      </div>

      <div className="metrics">
        <div className="metric">
          <div className="metric-v">{detection.label ?? '-'}</div>
          <div className="metric-k">静态模型</div>
        </div>
        <div className="metric">
          <div className="metric-v">{detection.confidence != null ? detection.confidence : '-'}</div>
          <div className="metric-k">置信度</div>
        </div>
        <div className="metric">
          <div className="metric-v">{probs.malware != null ? (probs.malware * 100).toFixed(1) + '%' : '-'}</div>
          <div className="metric-k">恶意概率</div>
        </div>
        <div className="metric">
          <div className="metric-v">{probs.benign != null ? (probs.benign * 100).toFixed(1) + '%' : '-'}</div>
          <div className="metric-k">良性概率</div>
        </div>
      </div>

      {detection.monitor && (
        <div className="mon-summary">
          <span>监控判定：{detection.monitor.monitor_verdict ?? '-'} · 风险分 {detection.monitor.risk_score ?? '-'}/100</span>
          <span>命中 {Array.isArray(detection.monitor.findings) ? detection.monitor.findings.length : 0} 项风险</span>
        </div>
      )}
    </section>
  )
}