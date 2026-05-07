export default function ConfigViewer({ content, filename }: { content: string; filename?: string }) {
  return (
    <div>
      {filename && (
        <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>
          {filename}
        </h3>
      )}
      <pre style={{
        fontSize: '12px',
        background: '#1f2937',
        color: '#e5e7eb',
        padding: '16px',
        borderRadius: '8px',
        overflow: 'auto',
        maxHeight: '400px',
        lineHeight: '1.5',
        fontFamily: 'monospace',
      }}>
        {content}
      </pre>
    </div>
  )
}
