import React from 'react'

// ============ 颜色语义（与现有 CSS 一致） ============
const C = {
  benign: '#30a46c',
  susp: '#f5a623',
  mal: '#e5484d',
  unknown: '#8b8b8b',
}

const STATE_META = {
  良性: { color: C.benign, seg: 'benign' },
  可疑待审: { color: C.susp, seg: 'susp' },
  恶意: { color: C.mal, seg: 'mal' },
  未知: { color: C.unknown, seg: 'unknown' },
}

// 半圆极坐标 → 平面坐标（圆心 100,100，半径 r，角度度制，0°=右）
function polar(cx, cy, r, deg) {
  const rad = (deg * Math.PI) / 180
  return { x: cx + r * Math.cos(rad), y: cy - r * Math.sin(rad) }
}
function arcPath(cx, cy, r, fromDeg, toDeg) {
  const a = polar(cx, cy, r, fromDeg)
  const b = polar(cx, cy, r, toDeg)
  const large = Math.abs(toDeg - fromDeg) > 180 ? 1 : 0
  return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} A ${r} ${r} 0 ${large} 1 ${b.x.toFixed(1)} ${b.y.toFixed(1)}`
}

// ============ 风险仪表盘（半圆 Gauge） ============
// risk: 0-100；confidence: 0-1；state: 四态文案
export function Gauge({ state = '未知', risk = 0, confidence }) {
  const meta = STATE_META[state] || STATE_META['未知']
  const r = 78, cx = 100, cy = 100
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v))
  const riskVal = clamp(Number(risk) || 0, 0, 100)
  // 指针角度：0(绿,左180°) → 100(红,右0°)
  const deg = 180 - riskVal * 1.8
  const tip = polar(cx, cy, 62, deg)
  const confPct = confidence != null ? Math.round(clamp(confidence, 0, 1) * 100) : null
  // 三段弧：绿 180→120(0-33) 黄 120→60(33-67) 红 60→0(67-100)
  return (
    <div className="viz-gauge">
      <svg viewBox="0 0 200 120" className="viz-svg">
        <path d={arcPath(cx, cy, r, 180, 120)} stroke={C.benign} strokeWidth="16" strokeLinecap="round" fill="none" />
        <path d={arcPath(cx, cy, r, 120, 60)} stroke={C.susp} strokeWidth="16" strokeLinecap="round" fill="none" />
        <path d={arcPath(cx, cy, r, 60, 0)} stroke={C.mal} strokeWidth="16" strokeLinecap="round" fill="none" />
        {/* 指针 */}
        <line x1={cx} y1={cy} x2={tip.x} y2={tip.y}
          stroke={meta.color} strokeWidth="4" strokeLinecap="round" />
        <circle cx={cx} cy={cy} r="7" fill={meta.color} />
        <text x={cx} y={cy + 34} textAnchor="middle" className="viz-gauge-state"
          fill={meta.color}>{state}</text>
        <text x={cx} y={cy + 50} textAnchor="middle" className="viz-gauge-risk">风险分 {Math.round(riskVal)}</text>
        {confPct != null && (
          <text x={150} y={12} textAnchor="end" className="viz-gauge-conf">置信度 {confPct}%</text>
        )}
      </svg>
    </div>
  )
}

// ============ 恶意/良性概率对比条 ============
export function ProbBar({ benign = 0, malware = 0 }) {
  const b = Math.round((Number(benign) || 0) * 100)
  const m = Math.round((Number(malware) || 0) * 100)
  const row = (label, val, color, side) => (
    <div className="prob-row" key={label}>
      <span className="prob-label">{label}</span>
      <div className="prob-track">
        <div className="prob-fill" style={{ width: `${Math.min(100, val)}%`, background: color }} />
      </div>
      <span className="prob-val">{val}%</span>
    </div>
  )
  return (
    <div className="viz-prob">
      {row('恶意概率', m, C.mal)}
      {row('良性概率', b, C.benign)}
    </div>
  )
}

// ============ 嵌入空间散点图（PCA-2D） ============
export function ClusterScatter({ point, clusters }) {
  if (!point || !Array.isArray(clusters) || clusters.length === 0) return null
  const all = []
  clusters.forEach((c) => c.points.forEach((p) => all.push(p)))
  if (point.x != null) all.push([point.x, point.y])
  if (all.length === 0) return null
  const xs = all.map((p) => p[0]), ys = all.map((p) => p[1])
  const xmin = Math.min(...xs), xmax = Math.max(...xs)
  const ymin = Math.min(...ys), ymax = Math.max(...ys)
  const spanX = (xmax - xmin) || 1, spanY = (ymax - ymin) || 1
  const PAD = 8, W = 300, H = 240
  const mapX = (x) => PAD + ((x - xmin) / spanX) * (W - PAD * 2)
  const mapY = (y) => PAD + ((y - ymin) / spanY) * (H - PAD * 2)
  return (
    <div className="viz-scatter">
      <div className="viz-title">嵌入空间位置 <span className="sub">（256 维 → PCA 2D）</span></div>
      <svg viewBox={`0 0 ${W} ${H}`} className="viz-svg">
        {clusters.map((c, i) => (
          <g key={i}>
            {c.points.map((p, j) => (
              <circle key={j} cx={mapX(p[0])} cy={mapY(p[1])} r="2.2"
                fill={c.color} opacity="0.35" />
            ))}
          </g>
        ))}
        {point.x != null && (
          <g>
            <circle cx={mapX(point.x)} cy={mapY(point.y)} r="10" fill="none"
              stroke="#111" strokeWidth="2" opacity="0.35" />
            <circle cx={mapX(point.x)} cy={mapY(point.y)} r="7" fill="#ff4500"
              stroke="#fff" strokeWidth="2" />
            <text x={mapX(point.x)} y={mapY(point.y) - 14} textAnchor="middle"
              className="viz-scatter-this">本样本</text>
          </g>
        )}
      </svg>
      <div className="viz-legend">
        {clusters.map((c, i) => (
          <span key={i} className="legend-item">
            <span className="legend-dot" style={{ background: c.color }} />{c.label}
          </span>
        ))}
        <span className="legend-item"><span className="legend-dot this" />本样本</span>
      </div>
    </div>
  )
}

// ============ 信号强度面板 ============
// items: [{label, value(0-100), color, note}]
export function SignalBar({ items = [] }) {
  if (!Array.isArray(items) || items.length === 0) return null
  return (
    <div className="viz-signals">
      <div className="viz-title">检测信号强度</div>
      {items.map((it, i) => (
        <div className="sig-row" key={i}>
          <span className="sig-label">{it.label}</span>
          <div className="sig-track">
            <div className="sig-fill" style={{
              width: `${Math.min(100, it.value || 0)}%`,
              background: it.color || C.unknown,
            }} />
          </div>
          <span className="sig-val">{it.note || `${Math.round(it.value || 0)}`}</span>
        </div>
      ))}
    </div>
  )
}
