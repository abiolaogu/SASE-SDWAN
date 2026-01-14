'use client';

import { ArrowUp, ArrowDown } from 'lucide-react';

export function TrafficChart() {
    const hours = Array.from({ length: 24 }, (_, i) => i);
    const data = hours.map((h) => ({
        hour: h,
        inbound: Math.floor(Math.random() * 500 + 200),
        outbound: Math.floor(Math.random() * 400 + 150),
    }));

    const maxValue = Math.max(...data.flatMap((d) => [d.inbound, d.outbound]));

    return (
        <div className="bg-card border border-border rounded-xl">
            <div className="p-4 border-b border-border flex items-center justify-between">
                <div>
                    <h3 className="font-semibold">Traffic (24h)</h3>
                    <p className="text-sm text-muted-foreground">Inbound / Outbound</p>
                </div>
                <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-2">
                        <ArrowDown className="w-4 h-4 text-green-500" />
                        <span>2.4 TB</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <ArrowUp className="w-4 h-4 text-blue-500" />
                        <span>1.8 TB</span>
                    </div>
                </div>
            </div>

            <div className="p-4">
                <div className="flex items-end gap-1 h-48">
                    {data.map((d, i) => (
                        <div key={i} className="flex-1 flex flex-col gap-0.5">
                            <div
                                className="bg-green-500/80 rounded-t transition-all duration-300"
                                style={{ height: `${(d.inbound / maxValue) * 100}%` }}
                            />
                            <div
                                className="bg-blue-500/80 rounded-b transition-all duration-300"
                                style={{ height: `${(d.outbound / maxValue) * 100}%` }}
                            />
                        </div>
                    ))}
                </div>
                <div className="flex justify-between mt-2 text-xs text-muted-foreground">
                    <span>00:00</span>
                    <span>06:00</span>
                    <span>12:00</span>
                    <span>18:00</span>
                    <span>24:00</span>
                </div>
            </div>
        </div>
    );
}
