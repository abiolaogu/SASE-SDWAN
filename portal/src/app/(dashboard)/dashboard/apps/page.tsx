'use client';

import { Plus, Search, Globe, Lock, CheckCircle, AlertCircle, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';

const apps = [
    { id: 1, name: 'Internal Wiki', type: 'HTTP', host: 'wiki.internal.acme.com', status: 'healthy', users: 245, requests: '12.4K/day' },
    { id: 2, name: 'Git Server', type: 'SSH', host: 'git.internal.acme.com:22', status: 'healthy', users: 87, requests: '8.2K/day' },
    { id: 3, name: 'Dev Database', type: 'TCP', host: 'db.internal.acme.com:5432', status: 'warning', users: 34, requests: '2.1K/day' },
    { id: 4, name: 'Jenkins CI', type: 'HTTP', host: 'jenkins.internal.acme.com', status: 'healthy', users: 56, requests: '5.6K/day' },
    { id: 5, name: 'Jira', type: 'HTTP', host: 'jira.internal.acme.com', status: 'healthy', users: 189, requests: '9.8K/day' },
    { id: 6, name: 'Kubernetes API', type: 'HTTPS', host: 'k8s.internal.acme.com:6443', status: 'healthy', users: 23, requests: '45.2K/day' },
];

export default function AppsPage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Applications</h1>
                    <p className="text-muted-foreground">Manage private application access (ZTNA)</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
                    <Plus className="w-4 h-4" />
                    Add Application
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold">42</p>
                    <p className="text-sm text-muted-foreground">Total Apps</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold text-green-500">40</p>
                    <p className="text-sm text-muted-foreground">Healthy</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold">156K</p>
                    <p className="text-sm text-muted-foreground">Daily Requests</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold">23ms</p>
                    <p className="text-sm text-muted-foreground">Avg Latency</p>
                </div>
            </div>

            {/* Search */}
            <div className="flex items-center gap-4">
                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                        type="text"
                        placeholder="Search applications..."
                        className="w-full pl-10 pr-4 py-2 bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                </div>
                <select className="px-4 py-2 bg-muted border border-border rounded-lg text-sm">
                    <option>All Types</option>
                    <option>HTTP/HTTPS</option>
                    <option>TCP</option>
                    <option>SSH</option>
                </select>
            </div>

            {/* Apps grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {apps.map((app) => (
                    <div
                        key={app.id}
                        className="bg-card border border-border rounded-xl p-6 hover:border-primary/50 transition-colors cursor-pointer group"
                    >
                        <div className="flex items-start justify-between">
                            <div className="p-2 rounded-lg bg-primary/10">
                                {app.type === 'HTTP' || app.type === 'HTTPS' ? (
                                    <Globe className="w-5 h-5 text-primary" />
                                ) : (
                                    <Lock className="w-5 h-5 text-primary" />
                                )}
                            </div>
                            <div className="flex items-center gap-1">
                                {app.status === 'healthy' ? (
                                    <CheckCircle className="w-4 h-4 text-green-500" />
                                ) : (
                                    <AlertCircle className="w-4 h-4 text-yellow-500" />
                                )}
                                <span className={cn(
                                    'text-xs capitalize',
                                    app.status === 'healthy' ? 'text-green-500' : 'text-yellow-500'
                                )}>
                                    {app.status}
                                </span>
                            </div>
                        </div>

                        <h3 className="mt-4 font-semibold">{app.name}</h3>
                        <p className="text-sm text-muted-foreground font-mono">{app.host}</p>

                        <div className="mt-4 flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">{app.users} users</span>
                            <span className="text-muted-foreground">{app.requests}</span>
                        </div>

                        <div className="mt-4 flex items-center gap-2">
                            <span className="text-xs px-2 py-1 rounded bg-muted">{app.type}</span>
                            <button className="ml-auto text-primary text-sm flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                Open <ExternalLink className="w-3 h-3" />
                            </button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
