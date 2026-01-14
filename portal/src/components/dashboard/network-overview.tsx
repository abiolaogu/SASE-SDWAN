'use client';

import { cn } from '@/lib/utils';

const sites = [
    { id: 1, name: 'HQ - New York', status: 'online', lat: 40.7, lng: -74, users: 245 },
    { id: 2, name: 'London Office', status: 'online', lat: 51.5, lng: -0.1, users: 128 },
    { id: 3, name: 'Singapore DC', status: 'warning', lat: 1.3, lng: 103.8, users: 87 },
    { id: 4, name: 'Tokyo Office', status: 'online', lat: 35.7, lng: 139.7, users: 156 },
    { id: 5, name: 'Sydney Branch', status: 'online', lat: -33.9, lng: 151.2, users: 64 },
    { id: 6, name: 'Frankfurt DC', status: 'online', lat: 50.1, lng: 8.7, users: 198 },
    { id: 7, name: 'Mumbai Office', status: 'offline', lat: 19.1, lng: 72.9, users: 0 },
];

export function NetworkOverview() {
    return (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="p-4 border-b border-border">
                <h3 className="font-semibold">Global Network</h3>
                <p className="text-sm text-muted-foreground">Site status across regions</p>
            </div>

            {/* Simplified world map representation */}
            <div className="relative h-64 bg-gradient-to-b from-muted/20 to-muted/5 p-4">
                <div className="absolute inset-0 flex items-center justify-center">
                    <svg viewBox="0 0 800 400" className="w-full h-full opacity-20">
                        {/* Simplified continents outline */}
                        <ellipse cx="400" cy="200" rx="350" ry="150" fill="none" stroke="currentColor" strokeWidth="1" />
                    </svg>
                </div>

                {/* Site markers */}
                {sites.map((site) => {
                    const x = ((site.lng + 180) / 360) * 100;
                    const y = ((90 - site.lat) / 180) * 100;
                    return (
                        <div
                            key={site.id}
                            className="absolute transform -translate-x-1/2 -translate-y-1/2 group cursor-pointer"
                            style={{ left: `${x}%`, top: `${y}%` }}
                        >
                            <div className={cn(
                                'w-3 h-3 rounded-full relative',
                                site.status === 'online' && 'bg-green-500',
                                site.status === 'warning' && 'bg-yellow-500',
                                site.status === 'offline' && 'bg-red-500'
                            )}>
                                {site.status === 'online' && (
                                    <span className="absolute inset-0 rounded-full bg-green-500 animate-ping opacity-50" />
                                )}
                            </div>

                            {/* Tooltip */}
                            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-popover border border-border rounded-lg shadow-lg opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
                                <p className="font-medium text-sm">{site.name}</p>
                                <p className="text-xs text-muted-foreground">{site.users} users</p>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Site list */}
            <div className="p-4 space-y-2 max-h-48 overflow-y-auto">
                {sites.map((site) => (
                    <div key={site.id} className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex items-center gap-3">
                            <span className={cn(
                                'w-2 h-2 rounded-full',
                                site.status === 'online' && 'bg-green-500',
                                site.status === 'warning' && 'bg-yellow-500',
                                site.status === 'offline' && 'bg-red-500'
                            )} />
                            <span className="text-sm font-medium">{site.name}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">{site.users} users</span>
                    </div>
                ))}
            </div>
        </div>
    );
}
