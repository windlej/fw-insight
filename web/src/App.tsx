import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Upload from './pages/Upload'
import Dashboard from './pages/Dashboard'
import Sessions from './pages/Sessions'
import Policies from './pages/Policies'
import NatRules from './pages/NatRules'
import Objects from './pages/Objects'
import Findings from './pages/Findings'
import RuleDetail from './pages/RuleDetail'
import Compare from './pages/Compare'
import Report from './pages/Report'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Sessions />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/dashboard/:id" element={<Dashboard />} />
        <Route path="/policies/:id" element={<Policies />} />
        <Route path="/nat/:id" element={<NatRules />} />
        <Route path="/objects/:id" element={<Objects />} />
        <Route path="/findings/:id" element={<Findings />} />
        <Route path="/rule/:id/:ruleId" element={<RuleDetail />} />
        <Route path="/compare" element={<Compare />} />
        <Route path="/report" element={<Report />} />
      </Routes>
    </Layout>
  )
}
