import { NavLink } from 'react-router-dom';
import {
    LayoutDashboard,
    Network,
    Route,
    Shield,
    FileText,
    Settings,
    Activity
} from 'lucide-react';

interface LayoutProps {
    children: React.ReactNode;
}

const navigation = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Sites & Devices', href: '/sites', icon: Network },
    { name: 'Tunnels', href: '/tunnels', icon: Route },
    { name: 'Policies', href: '/policies', icon: FileText },
    { name: 'Security', href: '/security', icon: Shield },
    { name: 'Settings', href: '/settings', icon: Settings },
];

export default function Layout({ children }: LayoutProps) {
    return (
        <div className="layout">
            <aside className="sidebar">
                <div className="sidebar-logo">
                    <Activity size={28} color="#3b82f6" />
                    <h1>OpenSASE</h1>
                </div>

                <nav className="sidebar-nav">
                    {navigation.map((item) => (
                        <NavLink
                            key={item.name}
                            to={item.href}
                            className={({ isActive }) =>
                                `nav-link ${isActive ? 'active' : ''}`
                            }
                        >
                            <item.icon size={20} />
                            {item.name}
                        </NavLink>
                    ))}
                </nav>

                <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{
                            width: '36px',
                            height: '36px',
                            borderRadius: '50%',
                            background: 'var(--accent-primary)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 600
                        }}>
                            A
                        </div>
                        <div>
                            <div style={{ fontWeight: 500, fontSize: '14px' }}>Admin</div>
                            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                                admin@opensase.io
                            </div>
                        </div>
                    </div>
                </div>
            </aside>

            <main className="main-content">
                {children}
            </main>
        </div>
    );
}
