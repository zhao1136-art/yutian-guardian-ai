import React, { useRef, useState } from 'react'
import { predictFile } from '../api.js'
import ResultCard from './ResultCard.jsx'

export default function UploadPanel({ lastDetection, onDetected }) {
  const fileRef = useRef(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [fileName, setFileName] = useState('')
  const [detection, setDetection] = useState(lastDetection || null)

  const pick = (e) => {
    const f = e.target.files && e.target.files[0]
    if (f) setFileName(f.name)
  }

  const run = async () => {
    const f = fileRef.current && fileRef.current.files && fileRef.current.files[0]
    if (!f) { setErr('请先选择要检测的样本文件'); return }
    setErr(''); setBusy(true)
    try {
      const d = await predictFile(f)
      setDetection(d)
      onDetected(d)
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="upload-box">
        <input type="file" ref={fileRef} onChange={pick} />
        <p className="hint">{fileName ? `已选：${fileName}` : '选择 PE 样本（.exe/.dll/.sys/.scr/.com）上传检测'}</p>
        <button className="primary" onClick={run} disabled={busy}>
          {busy ? '检测中…' : '开始检测'}
        </button>
        {err && <p className="error">{err}</p>}
      </div>

      <ResultCard detection={detection} />

      {detection && (
        <p className="hint center">
          检测完成。可切到「AI 对话」用它追问结论或处置建议。
        </p>
      )}
    </section>
  )
}