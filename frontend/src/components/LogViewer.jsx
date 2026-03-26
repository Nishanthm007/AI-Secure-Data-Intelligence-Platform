import { useMemo } from 'react'
import styles from './LogViewer.module.css'

const RISK_LINE_CLASS = {
  critical: styles.lineCritical,
  high: styles.lineHigh,
  medium: styles.lineMedium,
  low: styles.lineLow,
}

const RISK_BADGE = {
  critical: { label: 'CRIT', cls: styles.badgeCritical },
  high: { label: 'HIGH', cls: styles.badgeHigh },
  medium: { label: 'MED', cls: styles.badgeMedium },
  low: { label: 'LOW', cls: styles.badgeLow },
}

export default function LogViewer({ content, lineRisks }) {
  const lines = useMemo(() => (content || '').split('\n'), [content])

  if (!content) return null

  return (
    <div className={styles.viewer}>
      <div className={styles.header}>
        <span>📜 Log Viewer</span>
        <span className={styles.lineCount}>{lines.length} lines</span>
      </div>
      <div className={styles.body}>
        <div className={styles.lineNumbers}>
          {lines.map((_, i) => (
            <div key={i} className={styles.lineNum}>{i + 1}</div>
          ))}
        </div>
        <div className={styles.code}>
          {lines.map((line, i) => {
            const lineNum = String(i + 1)
            const risk = lineRisks?.[lineNum]
            const cls = risk ? RISK_LINE_CLASS[risk] : ''
            const badge = risk ? RISK_BADGE[risk] : null
            return (
              <div key={i} className={`${styles.line} ${cls}`} title={risk ? `Risk: ${risk}` : ''}>
                <span className={styles.lineText}>{line || ' '}</span>
                {badge && (
                  <span className={`${styles.riskBadge} ${badge.cls}`}>{badge.label}</span>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
