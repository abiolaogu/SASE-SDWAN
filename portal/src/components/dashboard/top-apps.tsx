'use client';

const apps = [
    { name: 'Microsoft 365', bytes: 847293847, percent: 28 },
    { name: 'Salesforce', bytes: 523847293, percent: 17 },
    { name: 'Zoom', bytes: 412938472, percent: 14 },
    { name: 'Slack', bytes: 298374829, percent: 10 },
    { name: 'AWS S3', bytes: 238472938, percent: 8 },
    { name: 'Other', bytes: 692847382, percent: 23 },
];

export function TopApps() {
    return (
        <div className="bg-card border border-border rounded-xl h-full">
            <div className="p-4 border-b border-border">
                <h3 className="font-semibold">Top Applications</h3>
                <p className="text-sm text-muted-foreground">By bandwidth usage</p>
            </div>

            <div className="p-4 space-y-4">
                {apps.map((app) => (
                    <div key={app.name} className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                            <span className="font-medium">{app.name}</span>
                            <span className="text-muted-foreground">{app.percent}%</span>
                        </div>
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                            <div
                                className="h-full bg-primary rounded-full transition-all duration-500"
                                style={{ width: `${app.percent}%` }}
                            />
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
