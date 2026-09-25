import React from 'react'
import { Gauge, ProbBar, ClusterScatter, SignalBar } from './Viz.jsx'

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
  const sig = detection.signature || {}
  const mon = detection.monitor || {}
  const risk = mon.risk_score ?? 0

  // 仪表盘指针按融合判定定级（恶意→红区 / 可疑→黄区 / 良性→绿区 / 未知→中位）
  // 不直接用监控风险分：监控分衡量系统侧异常，与样本恶意性无关（样本检测时常为 0）
  const THREAT_BY_STATE = { 恶意: 92, 可疑待审: 55, 良性: 8, 未知: 50 }
  const gaugeRisk = THREAT_BY_STATE[state] ?? 50

  // 信号强度面板（CNN 概率 / 签名命中 / 监控风险分）
  const sigNote = sig.malicious
    ? `命中${sig.total_hits ?? 0}处：${(sig.sig_hits || []).slice(0, 3).join('、')}`
    : '未命中'
  const signals = [
    { label: 'CNN 模型（恶意倾向）', value: (probs.malware ?? 0) * 100, color: '#e5484d', note: `${Math.round((probs.malware ?? 0) * 100)}%` },
    { label: '特征签名库', value: sig.malicious ? 100 : 0, color: sig.malicious ? '#e5484d' : '#8b8b8b', note: sigNote },
    { label: '系统监控风险分', value: risk, color: '#f5a623', note: `${Math.round(risk)}/100` },
  ]

  return (
    <section className="card result">
      <div className={`state-badge ${st.cls}`}>
        <span className="state-icon">{st.icon}</span>
        <div>
          <div className="state-label">{state}</div>
          <div className="state-sub">融合判定</div>
        </div>
      </div>

      <Gauge state={state} risk={gaugeRisk} confidence={detection.confidence} />

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

      <ProbBar benign={probs.benign} malware={probs.malware} />

      {sig.malicious && (
        <div className="sig-tags">
          {sig.md5_hit && <span className="sig-tag">MD5 哈希命中</span>}
          {(sig.sig_hits || []).slice(0, 5).map((t, i) => (
            <span className="sig-tag" key={i}>{t}</span>
          ))}
        </div>
      )}

      <ClusterScatter point={detection.viz?.point} clusters={detection.viz?.clusters} />

      <SignalBar items={signals} />

      {mon && (
        <div className="mon-summary">
          <span>监控判定：{mon.monitor_verdict ?? '-'} · 风险分 {risk ?? '-'}/100</span>
          <span>命中 {Array.isArray(mon.findings) ? mon.findings.length : 0} 项风险</span>
        </div>
      )}
    </section>
  )
}
