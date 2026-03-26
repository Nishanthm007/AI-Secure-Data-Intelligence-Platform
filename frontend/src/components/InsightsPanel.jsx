import styles from './InsightsPanel.module.css'

export default function InsightsPanel({ insights, summary, action }) {
  const actionConfig = {
    blocked: { icon: '🚫', label: 'Content Blocked', cls: styles.blocked },
    masked: { icon: '🔒', label: 'Content Masked', cls: styles.masked },
    allowed: { icon: '✅', label: 'Content Allowed', cls: styles.allowed },
  }
  const ac = actionConfig[action] || actionConfig.allowed

  return (
    <div className={styles.container}>
      {/* Summary */}
      <div className={styles.summary}>
        <span className={styles.summaryIcon}>🤖</span>
        <p className={styles.summaryText}>{summary}</p>
      </div>

      {/* Policy action */}
      <div className={`${styles.action} ${ac.cls}`}>
        <span>{ac.icon}</span>
        <span>Policy Action: <strong>{ac.label}</strong></span>
      </div>

      {/* AI insights */}
      {insights && insights.length > 0 && (
        <div className={styles.insightsList}>
          <h3 className={styles.insightsTitle}>
            <span>⚡</span> AI-Powered Security Insights
          </h3>
          <ul>
            {insights.map((insight, i) => (
              <li key={i} className={styles.insightItem}>
                <span className={styles.bullet}>›</span>
                <span>{insight}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
