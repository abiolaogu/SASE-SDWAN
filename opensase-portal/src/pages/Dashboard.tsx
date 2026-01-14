import {
    Network,
    Route,
    Shield,
    AlertTriangle,
    Activity,
    Zap
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

// Mock data for dashboard
const trafficData = [
    { time: '00:00', ingress: 45, egress: 32 },
    { time: '04:00', ingress: 32, egress: 28 },
    { time: '08:00', ingress: 65, egress: 55 },
    { time: '12:00', ingress: 85, egress: 72 },
    { time: '16:00', ingress: 78, egress: 68 },
    { time: '20:00', ingress: 52, egress: 45 },
    { time: '24:00', ingress: 40, egress: 35 },
];

const recentAlerts = [
    { id: 1, severity: 'critical', message: 'Tunnel to branch-c down', time: '2 min ago', site: 'branch-c' },
    { id: 2, severity: 'warning', message: 'High latency detected on WAN1', time: '15 min ago', site: 'branch-a' },
    { id: 3, severity: 'info', message: 'Policy update applied successfully', time: '1 hour ago', site: 'all' },
    { id: 4, severity: 'warning', message: 'IPS blocked 23 intrusion attempts', time: '2 hours ago', site: 'pop-nyc' },
];

const recentDevices = [
    { id: 1, name: 'branch-a', status: 'online', type: 'Branch', tunnels: 2, lastSeen: 'Just now' },
    { id: 2, name: 'branch-b', status: 'online', type: 'Branch', tunnels: 2, lastSeen: 'Just now' },
    { id: 3, name: 'branch-c', status: 'offline', type: 'Branch', tunnels: 0, lastSeen: '5 min ago' },
    { id: 4, name: 'pop-nyc', status: 'online', type: 'Hub', tunnels: 5, lastSeen: 'Just now' },
];

export default function Dashboard() {
    return (
        <div>
            <div className="page-header">
                <h2>Dashboard</h2>
                <p>OpenSASE Network Overview</p>
            </div>

            {/* Stats Grid */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-icon blue">
                        <Network size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>12</h3>
                        <p>Active Sites</p>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon green">
                        <Route size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>24</h3>
                        <p>Active Tunnels</p>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon purple">
                        <Zap size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>87.2 Gbps</h3>
                        <p>Current Throughput</p>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon orange">
                        <Shield size={24} />
                    </div>
                    <div className="stat-content">
                        <h3>1,247</h3>
                        <p>Threats Blocked (24h)</p>
                    </div>
                </div>
            </div>

            {/* Charts and Alerts Row */}
            <div className="grid-2" style={{ marginBottom: '24px' }}>
                {/* Traffic Chart */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Network Traffic (Gbps)</h3>
                        <span className="badge badge-success">
                            <Activity size={12} /> Live
                        </span>
                    </div>
                    <div className="chart-container">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={trafficData}>
                                <defs>
                                    <linearGradient id="colorIngress" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="colorEgress" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
                                <YAxis stroke="#64748b" fontSize={12} />
                                <Tooltip
                                    contentStyle={{
                                        background: '#1e293b',
                                        border: '1px solid #334155',
                                        borderRadius: '8px'
                                    }}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="ingress"
                                    stroke="#3b82f6"
                                    fill="url(#colorIngress)"
                                    strokeWidth={2}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="egress"
                                    stroke="#22c55e"
                                    fill="url(#colorEgress)"
                                    strokeWidth={2}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Recent Alerts */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Recent Alerts</h3>
                        <button className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '12px' }}>
                            View All
                        </button>
                    </div>
                    <div>
                        {recentAlerts.map(alert => (
                            <div key={alert.id} className={`alert-item ${alert.severity}`}>
                                <AlertTriangle size={18} />
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontWeight: 500 }}>{alert.message}</div>
                                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                                        {alert.site} • {alert.time}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Devices Table */}
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Recent Device Status</h3>
                    <button className="btn btn-primary">
                        Add Device
                    </button>
                </div>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Device Name</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Active Tunnels</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        {recentDevices.map(device => (
                            <tr key={device.id}>
                                <td style={{ fontWeight: 500 }}>{device.name}</td>
                                <td>{device.type}</td>
                                <td>
                                    <span className={`badge ${device.status === 'online' ? 'badge-success' : 'badge-danger'}`}>
                                        {device.status}
                                    </span>
                                </td>
                                <td>{device.tunnels}</td>
                                <td style={{ color: 'var(--text-secondary)' }}>{device.lastSeen}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
