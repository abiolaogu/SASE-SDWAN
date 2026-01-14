//! Looking Glass - Route Visibility
//!
//! Web interface for viewing BGP routes and session status.

use crate::{PeeringSession, BgpSessionState, IxpPort};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Route entry from BGP RIB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub prefix: String,
    pub next_hop: IpAddr,
    pub as_path: Vec<u32>,
    pub origin: RouteOrigin,
    pub local_pref: u32,
    pub med: Option<u32>,
    pub communities: Vec<String>,
    pub age_seconds: u64,
    pub valid: bool,
    pub best: bool,
    pub source: RouteSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RouteOrigin {
    Igp,
    Egp,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteSource {
    Peer { asn: u32, name: String },
    RouteServer { ixp: String },
    Transit { provider: String },
    Static,
}

/// Looking glass query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookingGlassQuery {
    pub query_type: QueryType,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryType {
    Prefix,
    AsPath,
    Community,
    Neighbor,
    Summary,
}

/// Looking glass response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookingGlassResponse {
    pub query: LookingGlassQuery,
    pub router_id: String,
    pub timestamp: i64,
    pub routes: Vec<RouteEntry>,
    pub execution_time_ms: u64,
}

/// Session summary for looking glass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub peer_asn: u32,
    pub peer_name: String,
    pub peer_ip: String,
    pub state: String,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub uptime: String,
    pub last_update: String,
}

/// Looking glass service
pub struct LookingGlass {
    router_id: String,
    bird_socket: String,
}

impl LookingGlass {
    pub fn new(router_id: &str, bird_socket: &str) -> Self {
        Self {
            router_id: router_id.to_string(),
            bird_socket: bird_socket.to_string(),
        }
    }

    /// Query routes for a prefix
    pub async fn query_prefix(&self, prefix: &str) -> LookingGlassResponse {
        let start = std::time::Instant::now();
        
        // Execute BIRD command: birdc show route for <prefix> all
        let routes = self.execute_bird_command(&format!("show route for {} all", prefix)).await;
        
        LookingGlassResponse {
            query: LookingGlassQuery {
                query_type: QueryType::Prefix,
                target: prefix.to_string(),
            },
            router_id: self.router_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            routes,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Query routes by AS path
    pub async fn query_as_path(&self, asn: u32) -> LookingGlassResponse {
        let start = std::time::Instant::now();
        
        let routes = self.execute_bird_command(&format!("show route where bgp_path ~ [= * {} * =]", asn)).await;
        
        LookingGlassResponse {
            query: LookingGlassQuery {
                query_type: QueryType::AsPath,
                target: asn.to_string(),
            },
            router_id: self.router_id.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            routes,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Get BGP session summary
    pub async fn get_session_summary(&self) -> Vec<SessionSummary> {
        // Execute BIRD command: birdc show protocols
        let output = self.execute_bird_raw("show protocols all").await;
        self.parse_protocols(&output)
    }

    /// Execute BIRD command and parse routes
    async fn execute_bird_command(&self, cmd: &str) -> Vec<RouteEntry> {
        // In production, connect to BIRD socket
        tracing::info!("BIRD command: birdc {}", cmd);
        
        // Return mock data for now
        vec![]
    }

    /// Execute raw BIRD command
    async fn execute_bird_raw(&self, cmd: &str) -> String {
        tracing::info!("BIRD command: birdc {}", cmd);
        String::new()
    }

    /// Parse BIRD protocol output
    fn parse_protocols(&self, _output: &str) -> Vec<SessionSummary> {
        vec![]
    }

    /// Format uptime
    fn format_uptime(seconds: u64) -> String {
        if seconds < 60 {
            format!("{}s", seconds)
        } else if seconds < 3600 {
            format!("{}m", seconds / 60)
        } else if seconds < 86400 {
            format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
        } else {
            format!("{}d {}h", seconds / 86400, (seconds % 86400) / 3600)
        }
    }
}

/// Generate HTML looking glass page
pub fn generate_looking_glass_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenSASE Looking Glass</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        
        h1 {
            font-size: 1.5rem;
            background: linear-gradient(135deg, var(--accent), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--bg-card);
            border-radius: 9999px;
            font-size: 0.875rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .query-box {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .query-form {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        select, input {
            flex: 1;
            min-width: 200px;
            padding: 0.75rem 1rem;
            background: var(--bg-dark);
            border: 1px solid #334155;
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 1rem;
        }
        
        button {
            padding: 0.75rem 2rem;
            background: var(--accent);
            border: none;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        button:hover { background: #2563eb; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
        }
        
        .results {
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
        }
        
        .results-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #334155;
            font-weight: 600;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        
        th {
            font-size: 0.75rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            font-weight: 600;
        }
        
        .as-path {
            font-family: monospace;
            font-size: 0.875rem;
        }
        
        .best-route {
            color: var(--success);
        }
        
        .route-invalid {
            color: var(--error);
            text-decoration: line-through;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌐 OpenSASE Looking Glass</h1>
            <div class="status-badge">
                <span class="status-dot"></span>
                <span id="session-count">Loading...</span>
            </div>
        </header>
        
        <div class="query-box">
            <form class="query-form" id="query-form">
                <select id="query-type">
                    <option value="prefix">Prefix Lookup</option>
                    <option value="aspath">AS Path Contains</option>
                    <option value="community">Community</option>
                    <option value="neighbor">Neighbor Routes</option>
                </select>
                <input type="text" id="query-input" placeholder="e.g., 8.8.8.0/24 or AS15169">
                <button type="submit">Query</button>
            </form>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Established Sessions</div>
                <div class="stat-value" id="established">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Prefixes</div>
                <div class="stat-value" id="prefixes">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">IXP Ports</div>
                <div class="stat-value" id="ports">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Traffic (Gbps)</div>
                <div class="stat-value" id="traffic">--</div>
            </div>
        </div>
        
        <div class="results">
            <div class="results-header">Query Results</div>
            <table>
                <thead>
                    <tr>
                        <th>Prefix</th>
                        <th>Next Hop</th>
                        <th>AS Path</th>
                        <th>Local Pref</th>
                        <th>Communities</th>
                        <th>Age</th>
                    </tr>
                </thead>
                <tbody id="results-body">
                    <tr>
                        <td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                            Enter a query above to view routes
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Fetch stats on load
        async function fetchStats() {
            try {
                const resp = await fetch('/api/looking-glass/stats');
                const data = await resp.json();
                document.getElementById('established').textContent = data.established_sessions;
                document.getElementById('prefixes').textContent = data.total_prefixes_received.toLocaleString();
                document.getElementById('ports').textContent = data.total_ixp_ports;
                document.getElementById('traffic').textContent = data.total_traffic_in_gbps.toFixed(1);
                document.getElementById('session-count').textContent = `${data.established_sessions} sessions`;
            } catch (e) {
                console.error('Failed to fetch stats:', e);
            }
        }
        
        // Query handler
        document.getElementById('query-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const type = document.getElementById('query-type').value;
            const target = document.getElementById('query-input').value;
            
            try {
                const resp = await fetch(`/api/looking-glass/query?type=${type}&target=${encodeURIComponent(target)}`);
                const data = await resp.json();
                renderResults(data.routes);
            } catch (e) {
                console.error('Query failed:', e);
            }
        });
        
        function renderResults(routes) {
            const tbody = document.getElementById('results-body');
            if (!routes || routes.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">No routes found</td></tr>';
                return;
            }
            
            tbody.innerHTML = routes.map(r => `
                <tr class="${r.best ? 'best-route' : ''} ${!r.valid ? 'route-invalid' : ''}">
                    <td>${r.prefix} ${r.best ? '✓' : ''}</td>
                    <td>${r.next_hop}</td>
                    <td class="as-path">${r.as_path.join(' ')}</td>
                    <td>${r.local_pref}</td>
                    <td>${r.communities.slice(0, 3).join(', ')}</td>
                    <td>${formatAge(r.age_seconds)}</td>
                </tr>
            `).join('');
        }
        
        function formatAge(seconds) {
            if (seconds < 60) return seconds + 's';
            if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
            if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
            return Math.floor(seconds / 86400) + 'd';
        }
        
        fetchStats();
        setInterval(fetchStats, 30000);
    </script>
</body>
</html>
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looking_glass_html() {
        let html = generate_looking_glass_html();
        assert!(html.contains("OpenSASE Looking Glass"));
        assert!(html.contains("query-form"));
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(LookingGlass::format_uptime(30), "30s");
        assert_eq!(LookingGlass::format_uptime(90), "1m");
        assert_eq!(LookingGlass::format_uptime(3700), "1h 1m");
        assert_eq!(LookingGlass::format_uptime(90000), "1d 1h");
    }
}
