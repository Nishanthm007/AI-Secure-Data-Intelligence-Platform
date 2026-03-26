import { useState, useRef } from 'react'
import styles from './FileUpload.module.css'

export default function FileUpload({ onFileSelect, loading }) {
  const [dragging, setDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const inputRef = useRef(null)

  const accept = '.pdf,.doc,.docx,.txt,.log,.sql,.csv'

  const handleFile = (file) => {
    if (!file) return
    setSelectedFile(file)
    onFileSelect(file)
  }

  const onDragOver = (e) => {
    e.preventDefault()
    setDragging(true)
  }
  const onDragLeave = () => setDragging(false)
  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }
  const onInputChange = (e) => {
    handleFile(e.target.files[0])
  }

  return (
    <div
      className={`${styles.dropzone} ${dragging ? styles.dragging : ''} ${selectedFile ? styles.hasFile : ''}`}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      onClick={() => !loading && inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className={styles.hidden}
        onChange={onInputChange}
        disabled={loading}
      />
      {selectedFile ? (
        <div className={styles.fileInfo}>
          <span className={styles.fileIcon}>{getFileIcon(selectedFile.name)}</span>
          <div>
            <p className={styles.fileName}>{selectedFile.name}</p>
            <p className={styles.fileSize}>{formatSize(selectedFile.size)}</p>
          </div>
          <button
            className={styles.clearBtn}
            onClick={(e) => {
              e.stopPropagation()
              setSelectedFile(null)
              onFileSelect(null)
              if (inputRef.current) inputRef.current.value = ''
            }}
          >
            ✕
          </button>
        </div>
      ) : (
        <div className={styles.prompt}>
          <span className={styles.uploadIcon}>📂</span>
          <p className={styles.promptMain}>
            {dragging ? 'Drop your file here' : 'Drag & drop or click to upload'}
          </p>
          <p className={styles.promptSub}>Supports PDF, DOCX, TXT, LOG, SQL, CSV · Max 10 MB</p>
        </div>
      )}
    </div>
  )
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase()
  const icons = { pdf: '📄', doc: '📝', docx: '📝', txt: '📋', log: '📜', sql: '🗄️', csv: '📊' }
  return icons[ext] || '📁'
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
