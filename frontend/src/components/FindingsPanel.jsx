import RiskBadge from './RiskBadge'
import styles from './FindingsPanel.module.css'

const TYPE_ICONS = {
  password: '🔑',
  api_key: '🗝️',
  secret: '🔒',
  token: '🎫',
  aws_key: '☁️',
  jwt: '🎟️',
  private_key: '🗄️',
  connection_string: '🔌',
  url_with_credentials: '🔗',
  credit_card: '💳',
  ssn: '🪪',
  email: '📧',
  phone: '📞',
  ip_address: '🌐',
  stack_trace: '⚠️',
  debug_leak: '🐛',
  brute_force_attempt: '🚨',
  suspicious_ip_activity: '👁️',
  debug_mode_leak: '🔧',
  repeated_errors: '📉',
}

export default function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <div className={styles.empty}>
        <span>✅</span>
        <p>No sensitive data or security issues detected.</p>
      </div>
    )
  }

  // Group by risk level
  const grouped = { critical: [], high: [], medium: [], low: [] }
  findings.forEach((f) => {
    if (grouped[f.risk]) grouped[f.risk].push(f)
  })

  return (
    <div className={styles.container}>
      {['critical', 'high', 'medium', 'low'].map((level) => {
        const group = grouped[level]
        if (!group.length) return null
        return (
          <div key={level} className={styles.group}>
            <div className={styles.groupHeader}>
              <RiskBadge level={level} />
              <span className={styles.count}>{group.length} finding{group.length !== 1 ? 's' : ''}</span>
            </div>
            <div className={styles.findings}>
              {group.map((f, i) => (
                <div key={i} className={`${styles.finding} ${styles[level]}`}>
                  <div className={styles.findingHeader}>
                    <span className={styles.icon}>{TYPE_ICONS[f.type] || '🔍'}</span>
                    <span className={styles.type}>{f.type.replace(/_/g, ' ')}</span>
                    {f.line && (
                      <span className={styles.line}>Line {f.line}</span>
                    )}
                  </div>
                  {f.value && (
                    <code className={styles.value}>{f.value}</code>
                  )}
                  {f.context && (
                    <p className={styles.context}>{truncate(f.context, 100)}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) + '...' : str
}
