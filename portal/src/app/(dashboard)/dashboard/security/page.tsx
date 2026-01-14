'use client';

import { Plus, Shield, ChevronRight, Check, X } from 'lucide-react';
import { cn } from '@/lib/utils';

const policies = [
    {
        id: 1,
        name: 'Default Outbound',
        type: 'Firewall',
        rules: 12,
        status: 'active',
        updated: '2h ago',
    },
    {
        id: 2,
        name: 'Block Malware',
        type: 'IPS',
        rules: 8,
        status: 'active',
        updated: '1d ago',
    },
    {
        id: 3,
        name: 'URL Categories',
        type: 'URL Filter',
        rules: 24,
        status: 'active',
        updated: '3d ago',
    },
    {
        id: 4,
        name: 'DLP - PCI',
        type: 'DLP',
        rules: 6,
        status: 'staging',
        updated: '5m ago',
    },
    {
        id: 5,
        name: 'SSL Inspection',
        type: 'Decrypt',
        rules: 4,
        status: 'active',
        updated: '1w ago',
    },
];

const recentChanges = [
    { id: 1, action: 'added', rule: 'Block TikTok', policy: 'URL Categories', user: 'admin@acme.com', time: '5m ago' },
    { id: 2, action: 'modified', rule: 'Allow Office365', policy: 'Default Outbound', user: 'security@acme.com', time: '2h ago' },
    { id: 3, action: 'deleted', rule: 'Legacy Rule #4', policy: 'Default Outbound', user: 'admin@acme.com', time: '1d ago' },
];

export default function SecurityPage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Security Policies</h1>
                    <p className="text-muted-foreground">Manage firewall, IPS, URL filtering, and DLP policies</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
                    <Plus className="w-4 h-4" />
                    Create Policy
                </button>
            </div>

            {/* Policy cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {policies.map((policy) => (
                    <div
                        key={policy.id}
                        className="bg-card border border-border rounded-xl p-6 hover:border-primary/50 transition-colors cursor-pointer group"
                    >
                        <div className="flex items-start justify-between">
                            <div className="p-2 rounded-lg bg-primary/10">
                                <Shield className="w-5 h-5 text-primary" />
                            </div>
                            <span className={cn(
                                'text-xs px-2 py-1 rounded-full',
                                policy.status === 'active' && 'bg-green-500/10 text-green-500',
                                policy.status === 'staging' && 'bg-yellow-500/10 text-yellow-500'
                            )}>
                                {policy.status}
                            </span>
                        </div>

                        <h3 className="mt-4 font-semibold">{policy.name}</h3>
                        <p className="text-sm text-muted-foreground">{policy.type}</p>

                        <div className="mt-4 flex items-center justify-between">
                            <span className="text-sm text-muted-foreground">{policy.rules} rules</span>
                            <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                        </div>
                    </div>
                ))}
            </div>

            {/* Recent changes */}
            <div className="bg-card border border-border rounded-xl">
                <div className="p-4 border-b border-border">
                    <h3 className="font-semibold">Recent Changes</h3>
                    <p className="text-sm text-muted-foreground">Policy modifications audit log</p>
                </div>

                <div className="divide-y divide-border">
                    {recentChanges.map((change) => (
                        <div key={change.id} className="p-4 flex items-center gap-4">
                            <div className={cn(
                                'p-2 rounded-lg',
                                change.action === 'added' && 'bg-green-500/10 text-green-500',
                                change.action === 'modified' && 'bg-blue-500/10 text-blue-500',
                                change.action === 'deleted' && 'bg-red-500/10 text-red-500'
                            )}>
                                {change.action === 'added' && <Plus className="w-4 h-4" />}
                                {change.action === 'modified' && <Check className="w-4 h-4" />}
                                {change.action === 'deleted' && <X className="w-4 h-4" />}
                            </div>

                            <div className="flex-1">
                                <p className="text-sm">
                                    <span className="font-medium">{change.rule}</span>
                                    <span className="text-muted-foreground"> {change.action} in </span>
                                    <span className="font-medium">{change.policy}</span>
                                </p>
                                <p className="text-xs text-muted-foreground">{change.user}</p>
                            </div>

                            <span className="text-xs text-muted-foreground">{change.time}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
