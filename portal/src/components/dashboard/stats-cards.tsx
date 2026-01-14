'use client';

import { Globe, Users, Gauge, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';

const stats = [
    {
        name: 'Active Sites',
        value: '24',
        change: '+2',
        changeType: 'positive',
        icon: Globe,
    },
    {
        name: 'Connected Users',
        value: '1,847',
        change: '+156',
        changeType: 'positive',
        icon: Users,
    },
    {
        name: 'Throughput',
        value: '4.2 Gbps',
        change: '+12%',
        changeType: 'positive',
        icon: Gauge,
    },
    {
        name: 'Threats Blocked',
        value: '12,459',
        change: 'Today',
        changeType: 'neutral',
        icon: Shield,
    },
];

export function StatsCards() {
    return (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {stats.map((stat) => (
                <div
                    key={stat.name}
                    className="bg-card border border-border rounded-xl p-6"
                >
                    <div className="flex items-center justify-between">
                        <div className="p-2 rounded-lg bg-primary/10">
                            <stat.icon className="w-5 h-5 text-primary" />
                        </div>
                        <span
                            className={cn(
                                'text-xs font-medium px-2 py-1 rounded-full',
                                stat.changeType === 'positive' && 'bg-green-500/10 text-green-500',
                                stat.changeType === 'negative' && 'bg-red-500/10 text-red-500',
                                stat.changeType === 'neutral' && 'bg-muted text-muted-foreground'
                            )}
                        >
                            {stat.change}
                        </span>
                    </div>
                    <div className="mt-4">
                        <p className="text-2xl font-bold">{stat.value}</p>
                        <p className="text-sm text-muted-foreground">{stat.name}</p>
                    </div>
                </div>
            ))}
        </div>
    );
}
