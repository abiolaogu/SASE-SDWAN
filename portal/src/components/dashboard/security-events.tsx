'use client';

import { Shield, AlertTriangle, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

const events = [
    { id: 1, type: 'blocked', title: 'Malware blocked', source: '192.168.1.45', time: '2m ago' },
    { id: 2, type: 'warning', title: 'Suspicious DNS query', source: '10.0.0.23', time: '5m ago' },
    { id: 3, type: 'blocked', title: 'IPS signature match', source: '172.16.0.12', time: '8m ago' },
    { id: 4, type: 'info', title: 'Policy updated', source: 'admin@acme.com', time: '15m ago' },
    { id: 5, type: 'blocked', title: 'C2 communication blocked', source: '10.0.1.87', time: '23m ago' },
    { id: 6, type: 'warning', title: 'Failed login attempt', source: 'user@acme.com', time: '45m ago' },
];

const iconMap = {
    blocked: XCircle,
    warning: AlertTriangle,
    info: Shield,
};

const colorMap = {
    blocked: 'text-red-500 bg-red-500/10',
    warning: 'text-yellow-500 bg-yellow-500/10',
    info: 'text-blue-500 bg-blue-500/10',
};

export function SecurityEvents() {
    return (
        <div className="bg-card border border-border rounded-xl">
            <div className="p-4 border-b border-border flex items-center justify-between">
                <div>
                    <h3 className="font-semibold">Security Events</h3>
                    <p className="text-sm text-muted-foreground">Recent activity</p>
                </div>
                <button className="text-sm text-primary hover:underline">View all</button>
            </div>

            <div className="divide-y divide-border">
                {events.map((event) => {
                    const Icon = iconMap[event.type as keyof typeof iconMap];
                    const colors = colorMap[event.type as keyof typeof colorMap];

                    return (
                        <div key={event.id} className="p-4 flex items-center gap-4 hover:bg-muted/50 transition-colors">
                            <div className={cn('p-2 rounded-lg', colors)}>
                                <Icon className="w-4 h-4" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium">{event.title}</p>
                                <p className="text-xs text-muted-foreground truncate">{event.source}</p>
                            </div>
                            <span className="text-xs text-muted-foreground whitespace-nowrap">{event.time}</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
