import { useNavigate } from 'react-router-dom'
import { useState } from 'react'
import { useUploadSession, useParsers } from '../api/client'

export default function Upload() {
  const [file, setFile] = useState<File | null>(null)
  const [vendor, setVendor] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const navigate = useNavigate()

  const { data: parsersData } = useParsers()
  const parsers = parsersData?.parsers || ['paloalto']

  const upload = useUploadSession()

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    if (e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0])
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return

    try {
      const result = await upload.mutateAsync({ file, vendor: vendor || undefined })
      navigate(`/dashboard/${result.id}`)
    } catch (err) {
      console.error('Upload failed:', err)
      alert(`Upload failed: ${err instanceof Error ? err.message : 'Unknown error'}`)
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '24px' }}>Upload Firewall Config</h2>

      <form onSubmit={handleSubmit}>
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          style={{
            border: `2px dashed ${dragOver ? '#3b82f6' : '#d1d5db'}`,
            borderRadius: '12px',
            padding: '48px',
            textAlign: 'center',
            background: dragOver ? '#eff6ff' : '#f9fafb',
            marginBottom: '20px',
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
          onClick={() => document.getElementById('file-input')?.click()}
        >
          <input
            id="file-input"
            type="file"
            accept=".xml,.conf,.txt,.unf"
            onChange={e => e.target.files?.[0] && setFile(e.target.files[0])}
            style={{ display: 'none' }}
          />
          <div style={{ fontSize: '40px', marginBottom: '12px' }}>
            {file ? '📄' : '📁'}
          </div>
          <p style={{ fontSize: '16px', fontWeight: 500, marginBottom: '4px' }}>
            {file ? file.name : 'Drop your firewall config file here'}
          </p>
          <p style={{ fontSize: '13px', color: '#6b7280' }}>
            {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Supports Palo Alto XML, FortiGate CLI, UniFi configs'}
          </p>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '6px' }}>
            Vendor
          </label>
          <select
            value={vendor}
            onChange={e => setVendor(e.target.value)}
            style={{
              padding: '8px 12px',
              border: '1px solid #d1d5db',
              borderRadius: '6px',
              fontSize: '14px',
              width: '300px',
            }}
          >
            <option value="">Auto-detect</option>
            {parsers.map(p => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>

        <button
          type="submit"
          disabled={upload.isPending || !file}
          style={{
            padding: '10px 24px',
            background: (!file || upload.isPending) ? '#9ca3af' : '#3b82f6',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            fontSize: '14px',
            fontWeight: 500,
            cursor: (!file || upload.isPending) ? 'not-allowed' : 'pointer',
          }}
        >
          {upload.isPending ? 'Analyzing...' : 'Analyze Config'}
        </button>
      </form>

      {upload.isError && (
        <div style={{
          marginTop: '16px',
          padding: '12px',
          background: '#fef2f2',
          border: '1px solid #fecaca',
          borderRadius: '6px',
          color: '#dc2626',
          fontSize: '14px',
        }}>
          {upload.error.message}
        </div>
      )}
    </div>
  )
}
