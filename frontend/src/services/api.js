import axios from 'axios'

const BACKEND = import.meta.env.VITE_API_URL || ''
const BASE = `${BACKEND}/api/v1`

export const WS_BASE = import.meta.env.VITE_WS_URL ||
  (BACKEND ? BACKEND.replace(/^http/, 'ws') : `ws://${window.location.hostname}:8000`)

export const WS_ANALYZE = `${WS_BASE}/api/v1/ws/analyze`

export async function analyzeText({ inputType, content, options }) {
  const { data } = await axios.post(`${BASE}/analyze`, {
    input_type: inputType,
    content,
    options,
  })
  return data
}

export async function analyzeFile(file, options) {
  const form = new FormData()
  form.append('file', file)
  form.append('options', JSON.stringify(options))
  const { data } = await axios.post(`${BASE}/analyze/upload`, form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function checkHealth() {
  const { data } = await axios.get(`${BASE}/health`)
  return data
}
