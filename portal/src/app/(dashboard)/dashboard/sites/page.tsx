'use client';

import { Plus, Search, MoreVertical, Globe, Wifi, WifiOff } from 'lucide-react';
import { cn } from '@/lib/utils';

const sites = [
    { id: 1, name: 'HQ - New York', location: 'New York, USA', status: 'online', users: 245, bandwidth: '1.2 Gbps', tunnels: 3 },
    { id: 2, name: 'London Office', location: 'London, UK', status: 'online', users: 128, bandwidth: '850 Mbps', tunnels: 2 },
    { id: 3, name: 'Singapore DC', location: 'Singapore', status: 'warning', users: 87, bandwidth: '420 Mbps', tunnels: 2 },
    { id: 4, name: 'Tokyo Office', location: 'Tokyo, Japan', status: 'online', users: 156, bandwidth: '650 Mbps', tunnels: 2 },
    { id: 5, name: 'Sydney Branch', location: 'Sydney, Australia', status: 'online', users: 64, bandwidth: '320 Mbps', tunnels: 1 },
    { id: 6, name: 'Frankfurt DC', location: 'Frankfurt, Germany', status: 'online', users: 198, bandwidth: '980 Mbps', tunnels: 3 },
    { id: 7, name: 'Mumbai Office', location: 'Mumbai, India', status: 'offline', users: 0, bandwidth: '0 Mbps', tunnels: 0 },
];

export default function SitesPage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Sites</h1>
                    <p className="text-muted-foreground">Manage your network sites and WAN links</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
                    <Plus className="w-4 h-4" />
                    Add Site
                </button>
            </div>

            {/* Search and filters */}
            <div className="flex items-center gap-4">
                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                        type="text"
                        placeholder="Search sites..."
                        className="w-full pl-10 pr-4 py-2 bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                </div>
                <select className="px-4 py-2 bg-muted border border-border rounded-lg text-sm">
                    <option>All Status</option>
                    <option>Online</option>
                    <option>Warning</option>
                    <option>Offline</option>
                </select>
            </div>

            {/* Sites table */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <table className="w-full">
                    <thead>
                        <tr className="border-b border-border bg-muted/50">
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Site</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Status</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Users</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Bandwidth</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Tunnels</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3"></th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                        {sites.map((site) => (
                            <tr key={site.id} className="hover:bg-muted/50 transition-colors">
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 rounded-lg bg-primary/10">
                                            <Globe className="w-4 h-4 text-primary" />
                                        </div>
                                        <div>
                                            <p className="font-medium">{site.name}</p>
                                            <p className="text-sm text-muted-foreground">{site.location}</p>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-2">
                                        {site.status === 'online' ? (
                                            <Wifi className="w-4 h-4 text-green-500" />
                                        ) : site.status === 'warning' ? (
                                            <Wifi className="w-4 h-4 text-yellow-500" />
                                        ) : (
                                            <WifiOff className="w-4 h-4 text-red-500" />
                                        )}
                                        <span className={cn(
                                            'text-sm capitalize',
                                            site.status === 'online' && 'text-green-500',
                                            site.status === 'warning' && 'text-yellow-500',
                                            site.status === 'offline' && 'text-red-500'
                                        )}>
                                            {site.status}
                                        </span>
                                    </div>
                                </td>
                                <td className="px-6 py-4 text-sm">{site.users}</td>
                                <td className="px-6 py-4 text-sm">{site.bandwidth}</td>
                                <td className="px-6 py-4 text-sm">{site.tunnels}</td>
                                <td className="px-6 py-4">
                                    <button className="p-1 rounded hover:bg-muted">
                                        <MoreVertical className="w-4 h-4" />
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
