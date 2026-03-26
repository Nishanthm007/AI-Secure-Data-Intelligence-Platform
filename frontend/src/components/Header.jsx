import styles from './Header.module.css'

export default function Header({ aiEnabled }) {
  return (
    <header className={styles.header}>
      <div className={styles.brand}>
        <span className={styles.shield}>🛡️</span>
        <div>
          <h1 className={styles.title}>AI Secure Data Intelligence Platform</h1>
          <p className={styles.subtitle}>AI Gateway · Scanner · Log Analyzer · Risk Engine</p>
        </div>
      </div>
      <div className={styles.status}>
        <span className={`${styles.dot} ${aiEnabled ? styles.dotGreen : styles.dotYellow}`} />
        <span className={styles.statusText}>
          {aiEnabled ? 'AI Insights: Active' : 'AI Insights: Rule-based (no API key)'}
        </span>
      </div>
    </header>
  )
}
