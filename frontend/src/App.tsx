import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import DashboardPage from './pages/DashboardPage'
import ScansPage from './pages/ScansPage'
import GraphPage from './pages/GraphPage'
import TestResultsPage from './pages/TestResultsPage'
import ReportsPage from './pages/ReportsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="results" element={<TestResultsPage />} />
          <Route path="reports" element={<ReportsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
