import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Sites from './pages/Sites';
import Tunnels from './pages/Tunnels';
import Policies from './pages/Policies';
import Security from './pages/Security';
import Settings from './pages/Settings';

function App() {
    return (
        <Layout>
            <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/sites" element={<Sites />} />
                <Route path="/tunnels" element={<Tunnels />} />
                <Route path="/policies" element={<Policies />} />
                <Route path="/security" element={<Security />} />
                <Route path="/settings" element={<Settings />} />
            </Routes>
        </Layout>
    );
}

export default App;
