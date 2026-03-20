import axios from 'axios'

// Call the backend directly on localhost:8000
// This works in WSL2 since both browser and backend are on the same host
export const apiClient = axios.create({
  baseURL: 'http://localhost:8000',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

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
