import { NetworkOverview } from '@/components/dashboard/network-overview';
import { StatsCards } from '@/components/dashboard/stats-cards';
import { TrafficChart } from '@/components/dashboard/traffic-chart';
import { TopApps } from '@/components/dashboard/top-apps';
import { SecurityEvents } from '@/components/dashboard/security-events';

export default function DashboardPage() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold">Network Overview</h1>
                <p className="text-muted-foreground">Real-time status of your SASE deployment</p>
            </div>

            {/* Stats Cards */}
            <StatsCards />

            {/* World Map */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                <div className="xl:col-span-2">
                    <NetworkOverview />
                </div>
                <div>
                    <TopApps />
                </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <TrafficChart />
                <SecurityEvents />
            </div>
        </div>
    );
}
