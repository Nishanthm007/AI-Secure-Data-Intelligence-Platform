import styles from './RiskBadge.module.css'

const RISK_CONFIG = {
  low: { label: 'LOW', color: styles.low },
  medium: { label: 'MEDIUM', color: styles.medium },
  high: { label: 'HIGH', color: styles.high },
  critical: { label: 'CRITICAL', color: styles.critical },
}

export default function RiskBadge({ level, size = 'sm' }) {
  if (!level) return null
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.low
  return (
    <span className={`${styles.badge} ${cfg.color} ${size === 'lg' ? styles.lg : ''}`}>
      {cfg.label}
    </span>
  )
}
