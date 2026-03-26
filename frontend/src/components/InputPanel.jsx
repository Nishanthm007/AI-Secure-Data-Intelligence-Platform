import { useState } from 'react'
import FileUpload from './FileUpload'
import styles from './InputPanel.module.css'

const TABS = [
  { id: 'text', label: '✏️ Text', placeholder: 'Paste any text to scan for sensitive data...' },
  { id: 'log', label: '📜 Log File', placeholder: '2026-03-10 10:00:01 INFO User login email=admin@company.com password=admin123\nERROR stack trace: NullPointerException at service.java:45' },
  { id: 'sql', label: '🗄️ SQL', placeholder: "SELECT * FROM users WHERE email='admin@company.com' AND password='secret123';" },
  { id: 'chat', label: '💬 Chat', placeholder: 'User: My API key is sk-prod-xyz123\nBot: I can help with that...' },
  { id: 'file', label: '📂 File Upload', placeholder: '' },
]

const DEFAULT_OPTIONS = {
  mask: true,
  block_high_risk: true,
  log_analysis: true,
}

export default function InputPanel({ onAnalyze, loading }) {
  const [activeTab, setActiveTab] = useState('text')
  const [content, setContent] = useState('')
  const [file, setFile] = useState(null)
  const [options, setOptions] = useState(DEFAULT_OPTIONS)

  const currentTab = TABS.find((t) => t.id === activeTab)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (activeTab === 'file') {
      if (!file) return
      onAnalyze({ mode: 'file', file, options })
    } else {
      if (!content.trim()) return
      onAnalyze({ mode: 'text', inputType: activeTab, content, options })
    }
  }

  const canSubmit = activeTab === 'file' ? !!file : !!content.trim()

  return (
    <div className={styles.panel}>
      <div className={styles.tabs}>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={`${styles.tab} ${activeTab === tab.id ? styles.active : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className={styles.form}>
        {activeTab !== 'file' ? (
          <textarea
            className={styles.textarea}
            placeholder={currentTab.placeholder}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={10}
            spellCheck={false}
            disabled={loading}
          />
        ) : (
          <FileUpload onFileSelect={setFile} loading={loading} />
        )}

        {/* Options */}
        <div className={styles.options}>
          <span className={styles.optLabel}>Options:</span>
          {[
            { key: 'mask', label: '🔒 Mask sensitive data' },
            { key: 'block_high_risk', label: '🚫 Block high-risk content' },
            { key: 'log_analysis', label: '📊 Deep log analysis' },
          ].map(({ key, label }) => (
            <label key={key} className={styles.optCheck}>
              <input
                type="checkbox"
                checked={options[key]}
                onChange={(e) => setOptions((o) => ({ ...o, [key]: e.target.checked }))}
                disabled={loading}
              />
              {label}
            </label>
          ))}
        </div>

        <button
          type="submit"
          className={styles.analyzeBtn}
          disabled={!canSubmit || loading}
        >
          {loading ? (
            <>
              <span className={styles.spinner} />
              Analyzing...
            </>
          ) : (
            '🔍 Analyze'
          )}
        </button>
      </form>
    </div>
  )
}
