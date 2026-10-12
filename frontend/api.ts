export type RiskClass = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical'

export type Finding = { code: string; label: string; status: string; evidence: string; severity?: string }
export type IOC = { id?: string; type: string; value: string; normalized_value: string; source?: string; matched: boolean; match_details: Record<string, unknown> }
export type Analysis = { id: string; case_id?: string; filename: string; size_bytes: number; sha256: string; status: string; parsing_status: string; risk_score: number; risk_class: RiskClass; risk_reasons: Array<{ code: string; label: string; points: number; evidence: string }>; metadata: Record<string, unknown>; findings: Finding[]; limitations: string[]; page_count?: number; encrypted?: boolean; created_at: string; iocs: IOC[] }
export type Stats = { total_pdfs: number; suspicious_documents: number; extracted_iocs: number; threat_matches: number; feed_health: { configured: number; operational: number } }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, headers: { ...(init?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(init?.headers || {}) } })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export const api = {
  health: () => request<{ status: string; timestamp: string }>('/api/health'),
  stats: () => request<Stats>('/api/dashboard/stats'),
  activity: () => request<{ activity: Array<{ label: string; count: number }>; risk_distribution: Array<{ label: string; count: number }> }>('/api/dashboard/activity'),
  analyses: () => request<Analysis[]>('/api/analyses'),
  analysis: (id: string) => request<Analysis>(`/api/analyses/${id}`),
  upload: (file: File) => { const body = new FormData(); body.append('file', file); return request<Analysis>('/api/analyses', { method: 'POST', body }) },
  iocs: (params: URLSearchParams) => request<{ items: IOC[]; total: number; page: number; page_size: number }>(`/api/iocs?${params.toString()}`),
  osint: () => request<Array<{ id: string; indicator: string; indicator_type: string; provider: string; status: string; findings: unknown[]; created_at: string }>>('/api/osint/investigations'),
  lookup: (payload: { indicator: string; indicator_type: string; consent: boolean; providers: string[] }) => request<Record<string, unknown>>('/api/osint/lookup', { method: 'POST', body: JSON.stringify(payload) }),
  feeds: () => request<Array<{ id: string; name: string; provider: string; url: string; enabled: boolean; last_success_at?: string; last_error?: string; indicator_count: number; documentation?: string }>>('/api/feeds'),
  syncFeed: (id: string) => request<Record<string, unknown>>(`/api/feeds/${id}/sync`, { method: 'POST' }),
  cases: () => request<Array<{ id: string; case_number: string; title: string; status: string; analyst_notes: string; analyses: Array<{ id: string; filename: string; risk_score: number; risk_class: RiskClass; created_at: string }>; created_at: string }>>('/api/cases'),
  patchCase: (id: string, payload: { status?: string; analyst_notes?: string }) => request<Record<string, unknown>>(`/api/cases/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  settings: () => request<Record<string, unknown>>('/api/settings'),
  updateSettings: (payload: Record<string, unknown>) => request<Record<string, unknown>>('/api/settings', { method: 'PATCH', body: JSON.stringify(payload) }),
}
