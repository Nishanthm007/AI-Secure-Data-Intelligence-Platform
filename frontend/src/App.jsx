import { useState, useEffect } from 'react'
import Header from './components/Header'
import InputPanel from './components/InputPanel'
import ResultsPanel from './components/ResultsPanel'
import StreamPanel from './components/StreamPanel'
import CorrelatePanel from './components/CorrelatePanel'
import { analyzeText, analyzeFile, checkHealth } from './services/api'
import styles from './App.module.css'

export default function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [aiEnabled, setAiEnabled] = useState(false)
  const [activeView, setActiveView] = useState('analyze') // analyze | stream | correlate

  useEffect(() => {
    checkHealth()
      .then((h) => setAiEnabled(h.ai_enabled))
      .catch(() => {})
  }, [])

  const handleAnalyze = async ({ mode, inputType, content, file, options }) => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      let data
      if (mode === 'file') {
        data = await analyzeFile(file, options)
      } else {
        data = await analyzeText({ inputType, content, options })
      }
      setResult(data)
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        'Analysis failed. Make sure the backend is running on port 8000.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.app}>
      <Header aiEnabled={aiEnabled} />

      {/* Top-level navigation */}
      <nav className={styles.nav}>
        {[
          { id: 'analyze', label: '🔍 Analyze', desc: 'Scan any input' },
          { id: 'stream', label: '⚡ Stream', desc: 'Real-time WebSocket' },
          { id: 'correlate', label: '🔗 Correlate', desc: 'Cross-log detection' },
        ].map((v) => (
          <button
            key={v.id}
            className={`${styles.navBtn} ${activeView === v.id ? styles.navActive : ''}`}
            onClick={() => setActiveView(v.id)}
          >
            <span>{v.label}</span>
            <span className={styles.navDesc}>{v.desc}</span>
          </button>
        ))}
      </nav>

      <main className={styles.main}>
        {activeView === 'analyze' && (
          <div className={styles.grid}>
            {/* Left column: Input */}
            <div className={styles.inputCol}>
              <div className={styles.colHeader}>
                <h2 className={styles.colTitle}>Input</h2>
                <p className={styles.colSub}>Paste text, upload a file, or enter SQL / chat / log content</p>
              </div>
              <InputPanel onAnalyze={handleAnalyze} loading={loading} />
            </div>

            {/* Right column: Results */}
            <div className={styles.resultsCol}>
              <div className={styles.colHeader}>
                <h2 className={styles.colTitle}>Analysis Results</h2>
                <p className={styles.colSub}>Security findings, risk score, and AI-powered insights</p>
              </div>

              {error && (
                <div className={styles.errorBox}>
                  <span>⚠️</span>
                  <span>{error}</span>
                </div>
              )}

              {!result && !error && !loading && (
                <div className={styles.placeholder}>
                  <span className={styles.placeholderIcon}>🔍</span>
                  <p>Submit input to see analysis results</p>
                  <p className={styles.placeholderSub}>
                    The platform will scan for sensitive data, security risks, and generate AI insights.
                  </p>
                </div>
              )}

              {loading && (
                <div className={styles.loadingBox}>
                  <div className={styles.loadingSpinner} />
                  <div>
                    <p className={styles.loadingTitle}>Analyzing content...</p>
                    <p className={styles.loadingSub}>Running detection engine and AI analysis</p>
                  </div>
                </div>
              )}

              {result && !loading && <ResultsPanel result={result} />}
            </div>
          </div>
        )}

        {activeView === 'stream' && (
          <div className={styles.fullWidth}>
            <div className={styles.colHeader}>
              <h2 className={styles.colTitle}>Real-Time Log Streaming</h2>
              <p className={styles.colSub}>WebSocket-powered analysis — findings stream live as each line is processed</p>
            </div>
            <StreamPanel />
          </div>
        )}

        {activeView === 'correlate' && (
          <div className={styles.fullWidth}>
            <div className={styles.colHeader}>
              <h2 className={styles.colTitle}>Cross-Log Correlation</h2>
              <p className={styles.colSub}>Detect shared IPs, credentials, and coordinated brute-force attacks across multiple log sources</p>
            </div>
            <CorrelatePanel />
          </div>
        )}
      </main>

      <footer className={styles.footer}>
        <span>AI Secure Data Intelligence Platform · Hackathon 2026</span>
        <span className={styles.footerRight}>
          Backend: FastAPI · Frontend: React + Vite
        </span>
      </footer>
    </div>
  )
}
