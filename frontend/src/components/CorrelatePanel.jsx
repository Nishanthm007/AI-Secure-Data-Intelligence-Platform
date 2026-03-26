import { useState } from 'react'
import axios from 'axios'
import RiskBadge from './RiskBadge'
import styles from './CorrelatePanel.module.css'

const SEV_ICONS = {
  critical: '🚨',
  high: '⚠️',
  medium: '🔶',
  low: '🔵',
}

const TYPE_LABELS = {
  shared_ip: 'Shared IP Address',
  shared_email: 'Shared Email/Account',
  coordinated_brute_force: 'Coordinated Brute Force',
}

export default function CorrelatePanel() {
  const [logs, setLogs] = useState(['', ''])
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const updateLog = (idx, val) => {
    setLogs((prev) => prev.map((l, i) => (i === idx ? val : l)))
  }

  const addLog = () => {
    if (logs.length < 5) setLogs((prev) => [...prev, ''])
  }

  const removeLog = (idx) => {
    if (logs.length > 2) setLogs((prev) => prev.filter((_, i) => i !== idx))
  }

  const handleCorrelate = async () => {
    const filled = logs.filter((l) => l.trim())
    if (filled.length < 2) {
      setError('Fill in at least 2 log entries to correlate.')
      return
    }
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const { data } = await axios.post('/api/v1/correlate', { logs: filled })
      setResult(data)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Correlation failed.')
    } finally {
      setLoading(false)
    }
  }

  const RISK_COLORS = { low: '#3fb950', medium: '#d29922', high: '#f0883e', critical: '#f85149' }

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <span className={styles.badge}>🔗 Cross-Log Correlation</span>
        <p className={styles.desc}>
          Paste multiple log files to detect shared IPs, credentials, and coordinated attacks across systems.
        </p>
      </div>

      <div className={styles.body}>
        {/* Log inputs */}
        <div className={styles.logsSection}>
          {logs.map((log, idx) => (
            <div key={idx} className={styles.logBox}>
              <div className={styles.logBoxHeader}>
                <span className={styles.logLabel}>Log #{idx + 1}</span>
                {idx >= 2 && (
                  <button className={styles.removeBtn} onClick={() => removeLog(idx)}>✕</button>
                )}
              </div>
              <textarea
                className={styles.textarea}
                placeholder={`Paste log #${idx + 1} content here...`}
                value={log}
                onChange={(e) => updateLog(idx, e.target.value)}
                rows={7}
                disabled={loading}
                spellCheck={false}
              />
            </div>
          ))}

          <div className={styles.logActions}>
            {logs.length < 5 && (
              <button className={styles.addBtn} onClick={addLog} disabled={loading}>
                + Add Log
              </button>
            )}
            <button
              className={styles.correlateBtn}
              onClick={handleCorrelate}
              disabled={loading || logs.filter((l) => l.trim()).length < 2}
            >
              {loading ? (
                <><span className={styles.spinner} /> Correlating...</>
              ) : (
                '🔗 Correlate Logs'
              )}
            </button>
          </div>

          {error && <div className={styles.errorBox}>⚠️ {error}</div>}
        </div>

        {/* Results */}
        {result && (
          <div className={styles.results}>
            {/* Aggregate risk */}
            <div className={styles.aggregate}>
              <div className={styles.aggregateLeft}>
                <div className={styles.scoreCircle} style={{ '--rc': RISK_COLORS[result.aggregate_risk_level] }}>
                  <span className={styles.scoreNum}>{result.aggregate_risk_score}</span>
                  <span className={styles.scoreLabel}>AGG</span>
                </div>
                <div>
                  <RiskBadge level={result.aggregate_risk_level} size="lg" />
                  <p className={styles.aggregateMeta}>
                    {result.log_count} logs · {result.total_findings} total findings
                  </p>
                </div>
              </div>
              {/* Per-log risk chips */}
              <div className={styles.perLogRow}>
                {result.per_log.map((pl) => (
                  <div key={pl.log_index} className={styles.perLogChip}>
                    <span className={styles.perLogNum}>Log {pl.log_index}</span>
                    <RiskBadge level={pl.risk_level} />
                    <span className={styles.perLogScore}>Score {pl.risk_score}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Correlations */}
            <div className={styles.correlations}>
              <h3 className={styles.correlationsTitle}>
                🔗 {result.correlations.length} Cross-Log Correlation{result.correlations.length !== 1 ? 's' : ''} Found
              </h3>

              {result.correlations.length === 0 ? (
                <div className={styles.noCorrelations}>
                  ✅ No cross-log patterns detected between these log files.
                </div>
              ) : (
                result.correlations.map((c, i) => (
                  <div key={i} className={`${styles.correlationCard} ${styles[c.severity]}`}>
                    <div className={styles.corrHeader}>
                      <span className={styles.corrIcon}>{SEV_ICONS[c.severity]}</span>
                      <span className={styles.corrType}>{TYPE_LABELS[c.type] || c.type.replace(/_/g, ' ')}</span>
                      <RiskBadge level={c.severity} />
                      <div className={styles.corrLogs}>
                        {c.log_indices.map((li) => (
                          <span key={li} className={styles.logTag}>Log {li}</span>
                        ))}
                      </div>
                    </div>
                    <code className={styles.corrValue}>{c.value}</code>
                    <p className={styles.corrDesc}>{c.description}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
