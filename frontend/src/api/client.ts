import axios from 'axios'

export const apiClient = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// Response interceptor — surface errors cleanly
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ?? error.message ?? 'Unknown error'
    return Promise.reject(new Error(message))
  },
)

// ── Health API ────────────────────────────────────────────────────────────────
export const healthApi = {
  get: () => apiClient.get<{ status: string; version: string }>('/health'),
  ready: () => apiClient.get<{
    status: string
    checks: { postgres: boolean; neo4j: boolean }
  }>('/health/ready'),
}
