import React, { useEffect, useState } from 'react'
import { fetchMonitor } from '../api.js'

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
          <div className="mon-head">
            <span className={`pill ${data.monitor_verdict === '可疑待审' ? 'susp' : 'ok'}`}>
              判定：{data.monitor_verdict ?? '-'}
            </span>
            <span className="metric"><span className="metric-v">{data.risk_score ?? '-'}</span> 风险分 /100</span>
            <span className="metric"><span className="metric-v">
              {Array.isArray(data.findings) ? data.findings.length : 0}</span> 项风险</span>
          </div>

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