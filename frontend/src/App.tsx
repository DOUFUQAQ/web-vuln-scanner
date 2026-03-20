import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import ScanResults from './pages/ScanResults'
import Layout from './components/Layout'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="targets" element={<Targets />} />
          <Route path="results/:taskId" element={<ScanResults />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
