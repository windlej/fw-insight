import { useState } from 'react'
import { useReactTable, getCoreRowModel, flexRender, createColumnHelper } from '@tanstack/react-table'
import type { SecurityPolicy } from '../types'

const columnHelper = createColumnHelper<SecurityPolicy>()

const columns = [
  columnHelper.accessor('position', { header: '#', cell: info => info.getValue() }),
  columnHelper.accessor('name', { header: 'Name', cell: info => info.getValue() || info.row.original.id }),
  columnHelper.accessor('source.addresses', {
    header: 'Source',
    cell: info => (info.getValue() || []).join(', '),
  }),
  columnHelper.accessor('destination.addresses', {
    header: 'Destination',
    cell: info => (info.getValue() || []).join(', '),
  }),
  columnHelper.accessor('action', {
    header: 'Action',
    cell: info => (
      <span style={{
        color: info.getValue() === 'allow' ? '#16a34a' : '#dc2626',
        fontWeight: 600,
      }}>
        {info.getValue()}
      </span>
    ),
  }),
  columnHelper.accessor('enabled', {
    header: 'Enabled',
    cell: info => info.getValue() ? 'Yes' : 'No',
  }),
]

export default function PolicyTable({
  policies,
  onRowClick,
}: {
  policies: SecurityPolicy[]
  onRowClick?: (policy: SecurityPolicy) => void
}) {
  const [filter, setFilter] = useState('')

  const filtered = policies.filter(p => {
    if (!filter) return true
    const search = filter.toLowerCase()
    return (
      p.name?.toLowerCase().includes(search) ||
      p.id.toLowerCase().includes(search) ||
      p.action.includes(search)
    )
  })

  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  return (
    <div>
      <div style={{ marginBottom: '12px' }}>
        <input
          type="text"
          placeholder="Filter rules..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{
            padding: '8px 12px',
            border: '1px solid #d1d5db',
            borderRadius: '6px',
            fontSize: '14px',
            width: '300px',
          }}
        />
      </div>
      <table style={{
        width: '100%',
        borderCollapse: 'collapse',
        fontSize: '13px',
      }}>
        <thead>
          {table.getHeaderGroups().map(hg => (
            <tr key={hg.id}>
              {hg.headers.map(h => (
                <th key={h.id} style={{
                  background: '#f3f4f6',
                  border: '1px solid #d1d5db',
                  padding: '8px',
                  textAlign: 'left',
                }}>
                  {flexRender(h.column.columnDef.header, h.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map(row => (
            <tr
              key={row.id}
              onClick={() => onRowClick?.(row.original)}
              style={{
                cursor: onRowClick ? 'pointer' : 'default',
                background: !row.original.enabled ? '#f9fafb' : undefined,
                opacity: !row.original.enabled ? 0.6 : 1,
              }}
            >
              {row.getVisibleCells().map(cell => (
                <td key={cell.id} style={{
                  border: '1px solid #d1d5db',
                  padding: '6px 8px',
                  maxWidth: '200px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ marginTop: '8px', fontSize: '12px', color: '#6b7280' }}>
        Showing {filtered.length} of {policies.length} rules
      </div>
    </div>
  )
}
