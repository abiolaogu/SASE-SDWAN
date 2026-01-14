import { Settings as SettingsIcon, Server, Shield, Bell, User, Key, Database } from 'lucide-react';

export default function Settings() {
    return (
        <div>
            <div className="page-header">
                <h2>Settings</h2>
                <p>System configuration and preferences</p>
            </div>

            <div className="grid-2">
                {/* General Settings */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">General</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <div>
                            <label style={{ display: 'block', marginBottom: '6px', fontSize: '14px', fontWeight: 500 }}>
                                Organization Name
                            </label>
                            <input
                                type="text"
                                defaultValue="OpenSASE Lab"
                                style={{
                                    width: '100%',
                                    padding: '10px 14px',
                                    background: 'var(--bg-tertiary)',
                                    border: '1px solid var(--border-color)',
                                    borderRadius: '8px',
                                    color: 'var(--text-primary)',
                                    fontSize: '14px'
                                }}
                            />
                        </div>
                        <div>
                            <label style={{ display: 'block', marginBottom: '6px', fontSize: '14px', fontWeight: 500 }}>
                                Admin Email
                            </label>
                            <input
                                type="email"
                                defaultValue="admin@opensase.io"
                                style={{
                                    width: '100%',
                                    padding: '10px 14px',
                                    background: 'var(--bg-tertiary)',
                                    border: '1px solid var(--border-color)',
                                    borderRadius: '8px',
                                    color: 'var(--text-primary)',
                                    fontSize: '14px'
                                }}
                            />
                        </div>
                        <button className="btn btn-primary" style={{ alignSelf: 'flex-start' }}>
                            Save Changes
                        </button>
                    </div>
                </div>

                {/* Integration Settings */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Integrations</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {[
                            { name: 'FlexiWAN Controller', status: 'connected', icon: Server },
                            { name: 'VPP Data Plane', status: 'connected', icon: Database },
                            { name: 'Suricata IPS', status: 'connected', icon: Shield },
                            { name: 'Wazuh SIEM', status: 'disconnected', icon: Bell },
                        ].map(integration => (
                            <div
                                key={integration.name}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '12px',
                                    padding: '12px',
                                    background: 'var(--bg-tertiary)',
                                    borderRadius: '8px'
                                }}
                            >
                                <integration.icon size={20} />
                                <span style={{ flex: 1, fontWeight: 500 }}>{integration.name}</span>
                                <span className={`badge ${integration.status === 'connected' ? 'badge-success' : 'badge-danger'}`}>
                                    {integration.status}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Security Settings */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Security</h3>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <div>
                                <div style={{ fontWeight: 500 }}>Two-Factor Authentication</div>
                                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                                    Require 2FA for all admin logins
                                </div>
                            </div>
                            <input type="checkbox" defaultChecked style={{ width: '20px', height: '20px' }} />
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <div>
                                <div style={{ fontWeight: 500 }}>API Key Rotation</div>
                                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                                    Auto-rotate API keys every 30 days
                                </div>
                            </div>
                            <input type="checkbox" style={{ width: '20px', height: '20px' }} />
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <div>
                                <div style={{ fontWeight: 500 }}>Audit Logging</div>
                                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                                    Log all administrative actions
                                </div>
                            </div>
                            <input type="checkbox" defaultChecked style={{ width: '20px', height: '20px' }} />
                        </div>
                    </div>
                </div>

                {/* API Settings */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">API Access</h3>
                    </div>
                    <div>
                        <div style={{ marginBottom: '16px' }}>
                            <label style={{ display: 'block', marginBottom: '6px', fontSize: '14px', fontWeight: 500 }}>
                                API Endpoint
                            </label>
                            <div style={{
                                padding: '10px 14px',
                                background: 'var(--bg-primary)',
                                borderRadius: '8px',
                                fontFamily: 'monospace',
                                fontSize: '13px'
                            }}>
                                https://api.opensase.io/v1
                            </div>
                        </div>
                        <div>
                            <label style={{ display: 'block', marginBottom: '6px', fontSize: '14px', fontWeight: 500 }}>
                                API Key
                            </label>
                            <div style={{ display: 'flex', gap: '8px' }}>
                                <div style={{
                                    flex: 1,
                                    padding: '10px 14px',
                                    background: 'var(--bg-primary)',
                                    borderRadius: '8px',
                                    fontFamily: 'monospace',
                                    fontSize: '13px'
                                }}>
                                    ••••••••••••••••••••••••••••••••
                                </div>
                                <button className="btn btn-secondary">
                                    <Key size={16} />
                                    Regenerate
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
