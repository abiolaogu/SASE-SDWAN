'use client';

import { Plus, Search, MoreVertical, User, Laptop, Smartphone, Shield, CheckCircle, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

const users = [
    { id: 1, name: 'John Smith', email: 'john@acme.com', role: 'Admin', status: 'active', devices: 2, lastActive: '5m ago' },
    { id: 2, name: 'Sarah Johnson', email: 'sarah@acme.com', role: 'User', status: 'active', devices: 3, lastActive: '1h ago' },
    { id: 3, name: 'Mike Brown', email: 'mike@acme.com', role: 'User', status: 'active', devices: 1, lastActive: '2h ago' },
    { id: 4, name: 'Emily Davis', email: 'emily@acme.com', role: 'Network Admin', status: 'active', devices: 2, lastActive: '3h ago' },
    { id: 5, name: 'Alex Wilson', email: 'alex@acme.com', role: 'User', status: 'inactive', devices: 0, lastActive: '2d ago' },
    { id: 6, name: 'Lisa Anderson', email: 'lisa@acme.com', role: 'Security Admin', status: 'active', devices: 2, lastActive: '30m ago' },
];

const devices = [
    { id: 1, name: 'MacBook Pro', type: 'laptop', os: 'macOS 14.2', user: 'John Smith', compliant: true, lastSeen: '5m ago' },
    { id: 2, name: 'iPhone 15', type: 'mobile', os: 'iOS 17.2', user: 'John Smith', compliant: true, lastSeen: '10m ago' },
    { id: 3, name: 'Windows Desktop', type: 'laptop', os: 'Windows 11', user: 'Sarah Johnson', compliant: false, lastSeen: '1h ago' },
    { id: 4, name: 'Dell XPS 15', type: 'laptop', os: 'Windows 11', user: 'Mike Brown', compliant: true, lastSeen: '2h ago' },
];

export default function UsersPage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Users & Devices</h1>
                    <p className="text-muted-foreground">Manage user access and device compliance</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
                    <Plus className="w-4 h-4" />
                    Add User
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold">1,847</p>
                    <p className="text-sm text-muted-foreground">Total Users</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold text-green-500">1,623</p>
                    <p className="text-sm text-muted-foreground">Active Today</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold">3,421</p>
                    <p className="text-sm text-muted-foreground">Devices</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-2xl font-bold text-yellow-500">127</p>
                    <p className="text-sm text-muted-foreground">Non-Compliant</p>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-4 border-b border-border">
                <button className="px-4 py-2 text-sm font-medium text-primary border-b-2 border-primary">Users</button>
                <button className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground">Devices</button>
                <button className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground">Groups</button>
            </div>

            {/* Search */}
            <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                    type="text"
                    placeholder="Search users..."
                    className="w-full pl-10 pr-4 py-2 bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                />
            </div>

            {/* Users table */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <table className="w-full">
                    <thead>
                        <tr className="border-b border-border bg-muted/50">
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">User</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Role</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Status</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Devices</th>
                            <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Last Active</th>
                            <th className="px-6 py-3"></th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                        {users.map((user) => (
                            <tr key={user.id} className="hover:bg-muted/50 transition-colors">
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-3">
                                        <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                                            <User className="w-4 h-4 text-primary" />
                                        </div>
                                        <div>
                                            <p className="font-medium">{user.name}</p>
                                            <p className="text-sm text-muted-foreground">{user.email}</p>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <span className="text-sm px-2 py-1 rounded bg-muted">{user.role}</span>
                                </td>
                                <td className="px-6 py-4">
                                    <span className={cn(
                                        'flex items-center gap-1 text-sm',
                                        user.status === 'active' ? 'text-green-500' : 'text-muted-foreground'
                                    )}>
                                        <span className={cn(
                                            'w-2 h-2 rounded-full',
                                            user.status === 'active' ? 'bg-green-500' : 'bg-muted-foreground'
                                        )} />
                                        {user.status}
                                    </span>
                                </td>
                                <td className="px-6 py-4 text-sm">{user.devices}</td>
                                <td className="px-6 py-4 text-sm text-muted-foreground">{user.lastActive}</td>
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
