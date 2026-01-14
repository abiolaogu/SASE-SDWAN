'use client';

import { Download, Calendar, BarChart3, PieChart, TrendingUp } from 'lucide-react';

export default function AnalyticsPage() {
    const hours = Array.from({ length: 24 }, (_, i) => i);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Analytics</h1>
                    <p className="text-muted-foreground">Network and security insights</p>
                </div>
                <div className="flex items-center gap-4">
                    <select className="px-4 py-2 bg-muted border border-border rounded-lg text-sm">
                        <option>Last 24 hours</option>
                        <option>Last 7 days</option>
                        <option>Last 30 days</option>
                    </select>
                    <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
                        <Download className="w-4 h-4" />
                        Export
                    </button>
                </div>
            </div>

            {/* Key metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-card border border-border rounded-xl p-6">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <TrendingUp className="w-4 h-4" />
                        Total Bandwidth
                    </div>
                    <p className="mt-2 text-3xl font-bold">4.2 TB</p>
                    <p className="text-sm text-green-500">+12% from yesterday</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-6">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <BarChart3 className="w-4 h-4" />
                        Active Sessions
                    </div>
                    <p className="mt-2 text-3xl font-bold">12,847</p>
                    <p className="text-sm text-green-500">+8% from yesterday</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-6">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <PieChart className="w-4 h-4" />
                        Threats Blocked
                    </div>
                    <p className="mt-2 text-3xl font-bold">1,459</p>
                    <p className="text-sm text-red-500">+23% from yesterday</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-6">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Calendar className="w-4 h-4" />
                        Avg Response Time
                    </div>
                    <p className="mt-2 text-3xl font-bold">23ms</p>
                    <p className="text-sm text-green-500">-5% from yesterday</p>
                </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Bandwidth over time */}
                <div className="bg-card border border-border rounded-xl">
                    <div className="p-4 border-b border-border">
                        <h3 className="font-semibold">Bandwidth Usage</h3>
                        <p className="text-sm text-muted-foreground">Last 24 hours</p>
                    </div>
                    <div className="p-4">
                        <div className="flex items-end gap-1 h-48">
                            {hours.map((h) => {
                                const value = 30 + Math.sin(h / 3) * 20 + Math.random() * 30;
                                return (
                                    <div key={h} className="flex-1 flex flex-col justify-end">
                                        <div
                                            className="bg-primary/80 rounded-t transition-all duration-300 hover:bg-primary"
                                            style={{ height: `${value}%` }}
                                        />
                                    </div>
                                );
                            })}
                        </div>
                        <div className="flex justify-between mt-2 text-xs text-muted-foreground">
                            <span>00:00</span>
                            <span>06:00</span>
                            <span>12:00</span>
                            <span>18:00</span>
                            <span>Now</span>
                        </div>
                    </div>
                </div>

                {/* Traffic by category */}
                <div className="bg-card border border-border rounded-xl">
                    <div className="p-4 border-b border-border">
                        <h3 className="font-semibold">Traffic by Category</h3>
                        <p className="text-sm text-muted-foreground">Application breakdown</p>
                    </div>
                    <div className="p-4 space-y-4">
                        {[
                            { name: 'Business Apps', percent: 35, color: 'bg-blue-500' },
                            { name: 'Cloud Services', percent: 28, color: 'bg-green-500' },
                            { name: 'Collaboration', percent: 18, color: 'bg-purple-500' },
                            { name: 'Streaming', percent: 12, color: 'bg-yellow-500' },
                            { name: 'Other', percent: 7, color: 'bg-gray-500' },
                        ].map((cat) => (
                            <div key={cat.name} className="space-y-2">
                                <div className="flex items-center justify-between text-sm">
                                    <span>{cat.name}</span>
                                    <span className="text-muted-foreground">{cat.percent}%</span>
                                </div>
                                <div className="h-2 bg-muted rounded-full overflow-hidden">
                                    <div className={`h-full ${cat.color} rounded-full`} style={{ width: `${cat.percent}%` }} />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Reports */}
            <div className="bg-card border border-border rounded-xl">
                <div className="p-4 border-b border-border flex items-center justify-between">
                    <div>
                        <h3 className="font-semibold">Scheduled Reports</h3>
                        <p className="text-sm text-muted-foreground">Automated report delivery</p>
                    </div>
                    <button className="text-sm text-primary hover:underline">Create Report</button>
                </div>
                <div className="divide-y divide-border">
                    {[
                        { name: 'Weekly Security Summary', schedule: 'Every Monday at 9:00 AM', recipients: 3 },
                        { name: 'Monthly Bandwidth Report', schedule: '1st of every month', recipients: 5 },
                        { name: 'Daily Threat Report', schedule: 'Every day at 6:00 AM', recipients: 2 },
                    ].map((report, i) => (
                        <div key={i} className="p-4 flex items-center justify-between hover:bg-muted/50 transition-colors">
                            <div>
                                <p className="font-medium">{report.name}</p>
                                <p className="text-sm text-muted-foreground">{report.schedule}</p>
                            </div>
                            <span className="text-sm text-muted-foreground">{report.recipients} recipients</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
