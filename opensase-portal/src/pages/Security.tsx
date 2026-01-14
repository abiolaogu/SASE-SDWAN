import { Shield, AlertTriangle, CheckCircle, XCircle, Clock, Eye } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

const alertsData = [
    {
        id: '1',
        severity: 'critical',
        category: 'IPS',
        message: 'SQL Injection attempt blocked',
        source: '203.0.113.42',
        destination: '10.201.0.100',
        site: 'branch-a',
        timestamp: '2026-01-14 07:45:23',
        status: 'blocked'
    },
    {
        id: '2',
        severity: 'high',
        category: 'DLP',
        message: 'Credit card data detected in outbound traffic',
        source: '10.201.0.55',
        destination: '93.184.216.34',
        site: 'branch-a',
        timestamp: '2026-01-14 07:43:12',
        status: 'blocked'
    },
    {
        id: '3',
        severity: 'medium',
        category: 'URL Filter',
        message: 'Malware category URL blocked',
        source: '10.202.0.22',
        destination: '198.51.100.99',
        site: 'branch-b',
        timestamp: '2026-01-14 07:40:55',
        status: 'blocked'
    },
    {
        id: '4',
        severity: 'low',
        category: 'CASB',
        message: 'Unsanctioned SaaS application detected',
        source: '10.201.0.88',
        destination: 'dropbox.com',
        site: 'branch-a',
        timestamp: '2026-01-14 07:35:01',
        status: 'allowed'
    },
];

const threatCategories = [
    { name: 'Malware', value: 342, color: '#ef4444' },
    { name: 'Phishing', value: 218, color: '#f59e0b' },
    { name: 'Intrusion', value: 156, color: '#8b5cf6' },
    { name: 'Data Leak', value: 89, color: '#3b82f6' },
    { name: 'Policy', value: 442, color: '#22c55e' },
];

const hourlyThreats = [
    { hour: '00', threats: 45 },
    { hour: '04', threats: 23 },
    { hour: '08', threats: 78 },
    { hour: '12', threats: 156 },
    { hour: '16', threats: 134 },
    { hour: '20', threats: 67 },
];

export default function Security() {
    return (
        <div>
            <div className="page-header">
                <h2>Security</h2>
                <p>Threat detection, IPS, DLP, and security analytics</p>
            </div>

            {/* Security Stats */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-icon red">
                        <XCircle size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>1,247</h3>
                        <p>Threats Blocked (24h)</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon orange">
                        <AlertTriangle size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>23</h3>
                        <p>Active Alerts</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon green">
                        <CheckCircle size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>99.2%</h3>
                        <p>Block Rate</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon blue">
                        <Shield size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>4,521</h3>
                        <p>IPS Rules Active</p>
                    </div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="grid-2" style={{ marginBottom: '24px' }}>
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Threats by Category</h3>
                    </div>
                    <div style={{ height: '250px', display: 'flex', alignItems: 'center' }}>
                        <ResponsiveContainer width="60%" height="100%">
                            <PieChart>
                                <Pie
                                    data={threatCategories}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={90}
                                    dataKey="value"
                                >
                                    {threatCategories.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                            </PieChart>
                        </ResponsiveContainer>
                        <div style={{ flex: 1 }}>
                            {threatCategories.map(cat => (
                                <div key={cat.name} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                                    <div style={{ width: '12px', height: '12px', borderRadius: '2px', background: cat.color }} />
                                    <span style={{ fontSize: '14px' }}>{cat.name}</span>
                                    <span style={{ marginLeft: 'auto', fontWeight: 600 }}>{cat.value}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Hourly Threat Activity</h3>
                    </div>
                    <div style={{ height: '250px' }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={hourlyThreats}>
                                <XAxis dataKey="hour" stroke="#64748b" fontSize={12} />
                                <YAxis stroke="#64748b" fontSize={12} />
                                <Tooltip
                                    contentStyle={{
                                        background: '#1e293b',
                                        border: '1px solid #334155',
                                        borderRadius: '8px'
                                    }}
                                />
                                <Bar dataKey="threats" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* Recent Alerts Table */}
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Recent Security Events</h3>
                    <button className="btn btn-secondary">View All</button>
                </div>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Message</th>
                            <th>Source → Dest</th>
                            <th>Site</th>
                            <th>Time</th>
                            <th>Status</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        {alertsData.map(alert => (
                            <tr key={alert.id}>
                                <td>
                                    <span className={`badge ${alert.severity === 'critical' ? 'badge-danger' :
                                            alert.severity === 'high' ? 'badge-warning' :
                                                alert.severity === 'medium' ? 'badge-info' :
                                                    'badge-success'
                                        }`}>
                                        {alert.severity}
                                    </span>
                                </td>
                                <td>{alert.category}</td>
                                <td style={{ maxWidth: '250px' }}>{alert.message}</td>
                                <td style={{ fontSize: '13px', fontFamily: 'monospace' }}>
                                    {alert.source} → {alert.destination}
                                </td>
                                <td>{alert.site}</td>
                                <td style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                                    <Clock size={12} style={{ display: 'inline', marginRight: '4px' }} />
                                    {alert.timestamp.split(' ')[1]}
                                </td>
                                <td>
                                    <span className={`badge ${alert.status === 'blocked' ? 'badge-danger' : 'badge-warning'}`}>
                                        {alert.status}
                                    </span>
                                </td>
                                <td>
                                    <button className="btn btn-secondary" style={{ padding: '6px' }}>
                                        <Eye size={14} />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
