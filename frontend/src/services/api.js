import axios from 'axios'

const BASE = '/api/v1'

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
