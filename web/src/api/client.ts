import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Session, SessionSummary, AnalysisResult } from '../types'

const API_BASE = '/api/v1'

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const err = await res.text()
    throw new Error(`API error ${res.status}: ${err}`)
  }
  return res.json()
}

export function useSessions() {
  return useQuery<{ sessions: SessionSummary[] }>({
    queryKey: ['sessions'],
    queryFn: () => apiFetch('/sessions'),
  })
}

export function useSession(id: string) {
  return useQuery<Session>({
    queryKey: ['session', id],
    queryFn: () => apiFetch(`/sessions/${id}`),
    enabled: !!id,
  })
}

export function useAnalysis(id: string) {
  return useQuery<AnalysisResult>({
    queryKey: ['analysis', id],
    queryFn: () => apiFetch(`/sessions/${id}/analysis`),
    enabled: !!id,
  })
}

export function useUploadSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ file, vendor }: { file: File; vendor?: string }) => {
      const form = new FormData()
      form.append('file', file)
      if (vendor) form.append('vendor', vendor)

      const res = await fetch(`${API_BASE}/sessions`, { method: 'POST', body: form })
      if (!res.ok) {
        const err = await res.text()
        throw new Error(`Upload failed: ${err}`)
      }
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    },
  })
}

export function useDeleteSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`${API_BASE}/sessions/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Delete failed')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    },
  })
}

export function useParsers() {
  return useQuery<{ parsers: string[] }>({
    queryKey: ['parsers'],
    queryFn: () => apiFetch('/parsers'),
  })
}
