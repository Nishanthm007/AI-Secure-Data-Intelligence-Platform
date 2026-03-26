import { useState } from 'react'
import RiskBadge from './RiskBadge'
import FindingsPanel from './FindingsPanel'
import InsightsPanel from './InsightsPanel'
import LogViewer from './LogViewer'
import styles from './ResultsPanel.module.css'
import { downloadReportPDF } from '../utils/pdfReport'

const RISK_COLORS = {
  low: '#3fb950',
  medium: '#d29922',
  high: '#f0883e',
  critical: '#f85149',
}

const TABS = ['Overview', 'Findings', 'Log Viewer', 'Masked Content', 'Raw JSON']

export default function ResultsPanel({ result }) {
  const [tab, setTab] = useState('Overview')

  if (!result) return null

  const { summary, content_type, findings, risk_score, risk_level, action, insights, masked_content, line_risks } = result
  const hasLog = content_type === 'log' || !!line_risks

  const visibleTabs = TABS.filter(t => {
    if (t === 'Log Viewer') return hasLog && masked_content
    if (t === 'Masked Content') return !!masked_content && content_type !== 'log'
    return true
  })

  // Risk gauge percentage (capped at score 20 = 100%)
  const gauge = Math.min((risk_score / 20) * 100, 100)
  const riskColor = RISK_COLORS[risk_level] || '#3fb950'

  // Finding type breakdown for mini chart
  const typeBreakdown = {}
  findings.forEach(f => {
    typeBreakdown[f.type] = (typeBreakdown[f.type] || 0) + 1
  })

  return (
    <div className={styles.panel}>
      {/* Risk score header */}
      <div className={styles.scoreHeader}>
        <div className={styles.scoreLeft}>
          <div className={styles.scoreCircle} style={{ '--risk-color': riskColor }}>
            <span className={styles.scoreNum}>{risk_score}</span>
            <span className={styles.scoreLabel}>RISK</span>
          </div>
          <div>
            <RiskBadge level={risk_level} size="lg" />
            <p className={styles.findingCount}>
              {findings.length} finding{findings.length !== 1 ? 's' : ''} · {content_type} input
            </p>
          </div>
        </div>
        {/* Mini gauge bar */}
        <div className={styles.gaugeWrap}>
          <div className={styles.gaugeBar}>
            <div
              className={styles.gaugeFill}
              style={{ width: `${gauge}%`, background: riskColor }}
            />
          </div>
          <div className={styles.gaugeLabels}>
            <span>0</span><span>LOW</span><span>MED</span><span>HIGH</span><span>CRIT</span>
          </div>
        </div>

        {/* Download PDF button */}
        <button
          className={styles.downloadBtn}
          onClick={() => downloadReportPDF(result)}
          title="Download analysis report as PDF"
        >
          ⬇ Download PDF
        </button>
      </div>

      {/* Tabs */}
      <div className={styles.tabs}>
        {visibleTabs.map(t => (
          <button
            key={t}
            className={`${styles.tab} ${tab === t ? styles.activeTab : ''}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className={styles.tabContent}>
        {tab === 'Overview' && (
          <InsightsPanel insights={insights} summary={summary} action={action} />
        )}
        {tab === 'Findings' && (
          <FindingsPanel findings={findings} />
        )}
        {tab === 'Log Viewer' && (
          <LogViewer content={masked_content} lineRisks={line_risks} />
        )}
        {tab === 'Masked Content' && (
          <div className={styles.maskedContent}>
            <pre className={styles.maskedPre}>{masked_content}</pre>
          </div>
        )}
        {tab === 'Raw JSON' && (
          <div className={styles.rawJson}>
            <div className={styles.rawJsonHeader}>
              <span className={styles.rawJsonLabel}>API Response</span>
              <button
                className={styles.copyBtn}
                onClick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2))}
              >
                Copy
              </button>
            </div>
            <pre className={styles.rawJsonPre}>{JSON.stringify(result, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  )
}
