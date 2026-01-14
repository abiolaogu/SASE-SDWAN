import { useState, useEffect } from 'react'
import './App.css'

// API base URL
const API_URL = import.meta.env.VITE_API_URL || ''

function App() {
    const [summary, setSummary] = useState(null)
    const [sites, setSites] = useState([])
    const [alerts, setAlerts] = useState([])
    const [apps, setApps] = useState([])
    const [policies, setPolicies] = useState([])
    const [loading, setLoading] = useState(true)
    const [activeTab, setActiveTab] = useState('overview')

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 30000) // Refresh every 30s
        return () => clearInterval(interval)
    }, [])

    const fetchData = async () => {
        try {
            const [summaryRes, sitesRes, alertsRes, appsRes, policiesRes] = await Promise.all([
                fetch(`${API_URL}/api/dashboard/summary`),
                fetch(`${API_URL}/api/sites`),
                fetch(`${API_URL}/api/alerts`),
                fetch(`${API_URL}/api/ztna/apps`),
                fetch(`${API_URL}/api/policies`),
            ])

            if (summaryRes.ok) setSummary(await summaryRes.json())
            if (sitesRes.ok) setSites(await sitesRes.json())
            if (alertsRes.ok) setAlerts(await alertsRes.json())
            if (appsRes.ok) setApps(await appsRes.json())
            if (policiesRes.ok) setPolicies(await policiesRes.json())
        } catch (error) {
            console.error('Failed to fetch data:', error)
        } finally {
            setLoading(false)
        }
    }

    if (loading) {
        return (
            <div className="loading">
                <div className="spinner"></div>
                <p>Loading OpenSASE-Lab Portal...</p>
            </div>
        )
    }

    return (
        <div className="app">
            <header className="header">
                <div className="logo">
                    <span className="logo-icon">🛡️</span>
                    <h1>OpenSASE-Lab</h1>
                </div>
                <nav className="nav">
                    <button
                        className={activeTab === 'overview' ? 'active' : ''}
                        onClick={() => setActiveTab('overview')}
                    >
                        Overview
                    </button>
                    <button
                        className={activeTab === 'sites' ? 'active' : ''}
                        onClick={() => setActiveTab('sites')}
                    >
                        Sites
                    </button>
                    <button
                        className={activeTab === 'security' ? 'active' : ''}
                        onClick={() => setActiveTab('security')}
                    >
                        Security
                    </button>
                    <button
                        className={activeTab === 'ztna' ? 'active' : ''}
                        onClick={() => setActiveTab('ztna')}
                    >
                        ZTNA
                    </button>
                </nav>
            </header>

            <main className="main">
                {activeTab === 'overview' && (
                    <div className="dashboard">
                        <div className="stats-grid">
                            <StatCard
                                title="Sites Online"
                                value={summary?.sites_online || 0}
                                total={summary?.sites_total || 0}
                                icon="🌐"
                                color="green"
                            />
                            <StatCard
                                title="Critical Alerts"
                                value={summary?.critical_alerts || 0}
                                icon="⚠️"
                                color={summary?.critical_alerts > 0 ? 'red' : 'green'}
                            />
                            <StatCard
                                title="ZTNA Sessions"
                                value={summary?.ztna_sessions || 0}
                                icon="🔐"
                                color="blue"
                            />
                            <StatCard
                                title="Active Policies"
                                value={summary?.policies_active || 0}
                                icon="📋"
                                color="purple"
                            />
                        </div>

                        <div className="panels">
                            <div className="panel">
                                <h2>Recent Alerts</h2>
                                <AlertList alerts={alerts.slice(0, 5)} />
                            </div>
                            <div className="panel">
                                <h2>ZTNA Applications</h2>
                                <AppList apps={apps} />
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'sites' && (
                    <div className="sites-view">
                        <h2>SD-WAN Sites</h2>
                        <SiteTable sites={sites} />
                    </div>
                )}

                {activeTab === 'security' && (
                    <div className="security-view">
                        <h2>Security Policies</h2>
                        <PolicyTable policies={policies} />
                        <h2>Security Alerts</h2>
                        <AlertList alerts={alerts} detailed />
                    </div>
                )}

                {activeTab === 'ztna' && (
                    <div className="ztna-view">
                        <h2>Zero Trust Applications</h2>
                        <AppTable apps={apps} />
                    </div>
                )}
            </main>

            <footer className="footer">
                <p>OpenSASE-Lab Portal v1.0.0 • <a href="http://localhost:3001" target="_blank">Grafana</a> • <a href="http://localhost:5601" target="_blank">Wazuh</a> • <a href="http://localhost:3000" target="_blank">FlexiWAN</a></p>
            </footer>
        </div>
    )
}

function StatCard({ title, value, total, icon, color }) {
    return (
        <div className={`stat-card ${color}`}>
            <div className="stat-icon">{icon}</div>
            <div className="stat-content">
                <h3>{title}</h3>
                <div className="stat-value">
                    {value}
                    {total !== undefined && <span className="stat-total">/{total}</span>}
                </div>
            </div>
        </div>
    )
}

function AlertList({ alerts, detailed }) {
    if (!alerts.length) {
        return <p className="empty">No alerts</p>
    }

    return (
        <ul className="alert-list">
            {alerts.map(alert => (
                <li key={alert.id} className={`alert-item ${alert.severity}`}>
                    <span className="alert-severity">{alert.severity.toUpperCase()}</span>
                    <span className="alert-message">{alert.message}</span>
                    {detailed && <span className="alert-source">{alert.source}</span>}
                </li>
            ))}
        </ul>
    )
}

function AppList({ apps }) {
    return (
        <ul className="app-list">
            {apps.map(app => (
                <li key={app.name} className="app-item">
                    <span className="app-name">{app.name}</span>
                    <span className="app-location">{app.location}</span>
                    <span className={`app-status ${app.status}`}>{app.status}</span>
                </li>
            ))}
        </ul>
    )
}

function SiteTable({ sites }) {
    return (
        <table className="data-table">
            <thead>
                <tr>
                    <th>Site</th>
                    <th>IP Address</th>
                    <th>Tunnel Status</th>
                    <th>Latency</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {sites.map(site => (
                    <tr key={site.name}>
                        <td>{site.name}</td>
                        <td><code>{site.ip}</code></td>
                        <td>{site.tunnel_status}</td>
                        <td>{site.latency_ms ? `${site.latency_ms}ms` : '-'}</td>
                        <td><span className={`status-badge ${site.status}`}>{site.status}</span></td>
                    </tr>
                ))}
            </tbody>
        </table>
    )
}

function PolicyTable({ policies }) {
    return (
        <table className="data-table">
            <thead>
                <tr>
                    <th>Policy</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Hits</th>
                </tr>
            </thead>
            <tbody>
                {policies.map(policy => (
                    <tr key={policy.name}>
                        <td>{policy.name}</td>
                        <td><span className="type-badge">{policy.type}</span></td>
                        <td>
                            <span className={`status-badge ${policy.enabled ? 'online' : 'offline'}`}>
                                {policy.enabled ? 'Active' : 'Disabled'}
                            </span>
                        </td>
                        <td>{policy.hits.toLocaleString()}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    )
}

function AppTable({ apps }) {
    return (
        <table className="data-table">
            <thead>
                <tr>
                    <th>Application</th>
                    <th>Service Name</th>
                    <th>Location</th>
                    <th>Sessions</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {apps.map(app => (
                    <tr key={app.name}>
                        <td>{app.name}</td>
                        <td><code>{app.service_name}</code></td>
                        <td>{app.location}</td>
                        <td>{app.active_sessions}</td>
                        <td><span className={`status-badge ${app.status}`}>{app.status}</span></td>
                    </tr>
                ))}
            </tbody>
        </table>
    )
}

export default App
