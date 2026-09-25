import React, { useEffect, useMemo, useState } from 'react'
import { fetchMonitor } from '../api.js'
import { Gauge } from './Viz.jsx'

// findings 按 rule 分组统计 → 横向条形分布（纯 SVG）
function RuleBars({ findings }) {
  const groups = useMemo(() => {
    const map = {}
    for (const f of findings || []) {
      const key = f.rule || '未分类'
      map[key] = (map[key] || 0) + 1
    }
    return Object.entries(map).sort((a, b) => b[1] - a[1])
  }, [findings])

  if (!groups.length) return null
  const max = groups[0][1]

  return (
    <div className="rule-dist">
      <div className="block-title">风险来源分布（按规则）</div>
      <svg viewBox={`0 0 300 ${groups.length * 26 + 8}`} className="rule-dist-svg" role="img" aria-label="风险来源分布">
        {groups.map(([rule, cnt], i) => {
          const y = i * 26 + 6
          const w = cnt / max * 220
          return (
            <g key={rule} transform={`translate(0 ${y})`}>
              <text x="0" y="12" className="rule-label">{rule}</text>
              <rect x="96" y="0" width={Math.max(w, cnt > 0 ? 4 : 0)} height="16" rx="3" className="rule-bar" />
              <text x="96" y="12" className="rule-count">{cnt}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

export default function MonitorPanel() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true); setErr('')
    try {
      const d = await fetchMonitor()
      setData(d)
    } catch (e) {
      setErr(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>敏感区域监控</h2>
        <button className="ghost" onClick={load} disabled={loading}>
          {loading ? '刷新中…' : '刷新'}
        </button>
      </div>

      {err && <p className="error">{err}</p>}

      {data && (
        <>
          <Gauge state={data.monitor_verdict || '未知'} risk={data.risk_score ?? 0} confidence={null} />

          <div className="mon-head">
            <span className={`pill ${data.monitor_verdict === '可疑待审' ? 'susp' : 'ok'}`}>
              判定：{data.monitor_verdict ?? '-'}
            </span>
            <span className="metric"><span className="metric-v">{data.risk_score ?? '-'}</span> 风险分 /100</span>
            <span className="metric"><span className="metric-v">
              {Array.isArray(data.findings) ? data.findings.length : 0}</span> 项风险</span>
          </div>

          <RuleBars findings={data.findings} />

          {Array.isArray(data.findings) && data.findings.length === 0 && (
            <p className="hint">未发现异常改动，敏感区域与基线一致。</p>
          )}

          <ul className="findings">
            {(data.findings || []).map((f, i) => (
              <li key={i}>
                <span className="tag">{f.area}</span>
                <span className="fdesc">{f.desc}</span>
                <span className="rule">{f.rule}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}
