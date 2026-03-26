import { useState, useRef, useCallback } from 'react'
import RiskBadge from './RiskBadge'
import styles from './StreamPanel.module.css'

const _apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const WS_URL = `${_apiBase.replace(/^http/, 'ws')}/api/v1/ws/analyze`

const RISK_ORDER = ['critical', 'high', 'medium', 'low']
const TYPE_ICONS = {
  password: '🔑', api_key: '🗝️', secret: '🔒', token: '🎫',
  aws_key: '☁️', jwt: '🎟️', email: '📧', phone: '📞',
  ip_address: '🌐', stack_trace: '⚠️', debug_leak: '🐛',
  brute_force_attempt: '🚨', suspicious_ip_activity: '👁️',
  credit_card: '💳', ssn: '🪪', connection_string: '🔌',
}

export default function StreamPanel() {
  const [content, setContent] = useState('')
  const [status, setStatus] = useState('idle') // idle | connecting | streaming | done | error
  const [progress, setProgress] = useState({ line: 0, total: 0, percent: 0 })
  const [findings, setFindings] = useState([])
  const [result, setResult] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const wsRef = useRef(null)
  const findingsEndRef = useRef(null)

  const scrollToBottom = () => {
    findingsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const startStream = useCallback(() => {
    if (!content.trim()) return

    setStatus('connecting')
    setFindings([])
    setResult(null)
    setErrorMsg('')
    setProgress({ line: 0, total: 0, percent: 0 })

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setStatus('streaming')
      ws.send(JSON.stringify({
        content,
        options: { mask: true, block_high_risk: false, log_analysis: true },
      }))
    }

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)

      if (msg.type === 'start') {
        setProgress({ line: 0, total: msg.total_lines, percent: 0 })
      } else if (msg.type === 'progress') {
        setProgress({ line: msg.line, total: msg.total, percent: msg.percent })
      } else if (msg.type === 'finding') {
        setFindings((prev) => [...prev, msg.finding])
        setTimeout(scrollToBottom, 50)
      } else if (msg.type === 'complete') {
        setResult(msg)
        setStatus('done')
        ws.close()
      } else if (msg.type === 'error') {
        setErrorMsg(msg.message)
        setStatus('error')
      }
    }

    ws.onerror = () => {
      setErrorMsg('WebSocket connection failed. Is the backend running?')
      setStatus('error')
    }

    ws.onclose = () => {
      if (status === 'streaming') setStatus('done')
    }
  }, [content])

  const stop = () => {
    wsRef.current?.close()
    setStatus('idle')
  }

  const isStreaming = status === 'streaming' || status === 'connecting'

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <span className={styles.badge}>⚡ Real-Time Streaming</span>
        <p className={styles.desc}>
          Analyzes your log line-by-line via WebSocket — findings appear live as they are detected.
        </p>
      </div>

      <div className={styles.body}>
        {/* Input */}
        <div className={styles.inputSide}>
          <textarea
            className={styles.textarea}
            placeholder="Paste log content here for real-time streaming analysis..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            disabled={isStreaming}
            rows={12}
            spellCheck={false}
          />
          <div className={styles.actions}>
            {!isStreaming ? (
              <button
                className={styles.startBtn}
                onClick={startStream}
                disabled={!content.trim()}
              >
                ⚡ Start Stream
              </button>
            ) : (
              <button className={styles.stopBtn} onClick={stop}>
                ⏹ Stop
              </button>
            )}
            {status !== 'idle' && (
              <button className={styles.resetBtn} onClick={() => {
                stop(); setStatus('idle'); setFindings([]); setResult(null)
              }}>
                ↺ Reset
              </button>
            )}
          </div>

          {/* Progress bar */}
          {(isStreaming || status === 'done') && (
            <div className={styles.progressWrap}>
              <div className={styles.progressBar}>
                <div
                  className={`${styles.progressFill} ${status === 'done' ? styles.progressDone : ''}`}
                  style={{ width: `${progress.percent}%` }}
                />
              </div>
              <div className={styles.progressMeta}>
                <span>Line {progress.line} / {progress.total}</span>
                <span>{progress.percent}%</span>
              </div>
            </div>
          )}

          {/* Final result card */}
          {result && (
            <div className={styles.resultCard}>
              <div className={styles.resultRow}>
                <RiskBadge level={result.risk_level} size="lg" />
                <span className={styles.score}>Risk Score: <strong>{result.risk_score}</strong></span>
                <span className={styles.findCount}>{result.total_findings} findings</span>
              </div>
              <p className={styles.summary}>{result.summary}</p>
              {result.insights?.length > 0 && (
                <ul className={styles.insights}>
                  {result.insights.map((ins, i) => (
                    <li key={i}><span className={styles.bullet}>›</span>{ins}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {status === 'error' && (
            <div className={styles.errorBox}>⚠️ {errorMsg}</div>
          )}
        </div>

        {/* Live findings feed */}
        <div className={styles.feedSide}>
          <div className={styles.feedHeader}>
            <span>Live Findings Feed</span>
            <span className={`${styles.liveIndicator} ${isStreaming ? styles.livePulse : ''}`}>
              {isStreaming ? '● LIVE' : findings.length > 0 ? `${findings.length} total` : '—'}
            </span>
          </div>
          <div className={styles.feed}>
            {findings.length === 0 && !isStreaming && (
              <div className={styles.feedEmpty}>Findings will appear here in real time</div>
            )}
            {findings.map((f, i) => (
              <div key={i} className={`${styles.feedItem} ${styles[f.risk]}`}>
                <div className={styles.feedItemHeader}>
                  <span>{TYPE_ICONS[f.type] || '🔍'}</span>
                  <span className={styles.feedType}>{f.type.replace(/_/g, ' ')}</span>
                  <RiskBadge level={f.risk} />
                  {f.line && <span className={styles.feedLine}>L{f.line}</span>}
                </div>
                {f.value && <code className={styles.feedValue}>{f.value}</code>}
              </div>
            ))}
            <div ref={findingsEndRef} />
          </div>
        </div>
      </div>
    </div>
  )
}
