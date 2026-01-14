/**
 * OpenSASE TypeScript SDK
 * 
 * A TypeScript client library for the OpenSASE API.
 * 
 * @example
 * ```typescript
 * import { OpenSASEClient } from '@opensase/sdk';
 * 
 * const client = new OpenSASEClient({ apiKey: 'ops_live_xxx' });
 * 
 * // List users
 * const users = await client.users.list();
 * 
 * // Create policy
 * const policy = await client.policies.create({
 *   name: 'Block Malware',
 *   action: 'block',
 *   conditions: [{ field: 'threat_category', operator: 'equals', value: 'malware' }]
 * });
 * ```
 */

export interface OpenSASEConfig {
    apiKey: string;
    baseUrl?: string;
}

export interface User {
    id: string;
    email: string;
    name: string;
    role: 'admin' | 'editor' | 'viewer';
    mfaEnabled: boolean;
    status: string;
    createdAt: string;
    lastLogin?: string;
}

export interface Policy {
    id: string;
    name: string;
    description: string;
    enabled: boolean;
    priority: number;
    conditions: PolicyCondition[];
    action: 'allow' | 'block' | 'isolate' | 'log';
    createdAt: string;
    updatedAt: string;
}

export interface PolicyCondition {
    field: string;
    operator: string;
    value: string;
}

export interface Site {
    id: string;
    name: string;
    location: string;
    status: 'active' | 'degraded' | 'offline';
    edgeCount: number;
    userCount: number;
}

export interface TunnelStats {
    tunnelId: string;
    latencyMs: number;
    jitterMs: number;
    packetLossPercent: number;
    rxBytes: number;
    txBytes: number;
}

export interface PaginatedResponse<T> {
    items: T[];
    total: number;
    page: number;
    perPage: number;
    totalPages: number;
}

export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: { code: string; message: string };
}

export class OpenSASEClient {
    private apiKey: string;
    private baseUrl: string;

    public users: UsersClient;
    public policies: PoliciesClient;
    public sites: SitesClient;
    public tunnels: TunnelsClient;
    public analytics: AnalyticsClient;

    constructor(config: OpenSASEConfig) {
        this.apiKey = config.apiKey;
        this.baseUrl = config.baseUrl || 'https://api.opensase.io/v1';

        this.users = new UsersClient(this);
        this.policies = new PoliciesClient(this);
        this.sites = new SitesClient(this);
        this.tunnels = new TunnelsClient(this);
        this.analytics = new AnalyticsClient(this);
    }

    async request<T>(method: string, path: string, body?: any): Promise<T> {
        const response = await fetch(`${this.baseUrl}${path}`, {
            method,
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json',
                'User-Agent': 'opensase-typescript/0.1.0'
            },
            body: body ? JSON.stringify(body) : undefined
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const json: ApiResponse<T> = await response.json();
        if (!json.success) {
            throw new Error(json.error?.message || 'Unknown error');
        }

        return json.data!;
    }
}

class UsersClient {
    constructor(private client: OpenSASEClient) { }

    async list(page = 1, perPage = 20): Promise<PaginatedResponse<User>> {
        return this.client.request('GET', `/users?page=${page}&per_page=${perPage}`);
    }

    async get(id: string): Promise<User> {
        return this.client.request('GET', `/users/${id}`);
    }

    async create(data: { email: string; name: string; role: string }): Promise<User> {
        return this.client.request('POST', '/users', data);
    }

    async delete(id: string): Promise<void> {
        return this.client.request('DELETE', `/users/${id}`);
    }
}

class PoliciesClient {
    constructor(private client: OpenSASEClient) { }

    async list(): Promise<PaginatedResponse<Policy>> {
        return this.client.request('GET', '/policies');
    }

    async get(id: string): Promise<Policy> {
        return this.client.request('GET', `/policies/${id}`);
    }

    async create(data: Partial<Policy>): Promise<Policy> {
        return this.client.request('POST', '/policies', data);
    }

    async update(id: string, data: Partial<Policy>): Promise<Policy> {
        return this.client.request('PUT', `/policies/${id}`, data);
    }

    async delete(id: string): Promise<void> {
        return this.client.request('DELETE', `/policies/${id}`);
    }
}

class SitesClient {
    constructor(private client: OpenSASEClient) { }

    async list(): Promise<PaginatedResponse<Site>> {
        return this.client.request('GET', '/sites');
    }

    async get(id: string): Promise<Site> {
        return this.client.request('GET', `/sites/${id}`);
    }
}

class TunnelsClient {
    constructor(private client: OpenSASEClient) { }

    async list(): Promise<PaginatedResponse<any>> {
        return this.client.request('GET', '/tunnels');
    }

    async stats(id: string): Promise<TunnelStats> {
        return this.client.request('GET', `/tunnels/${id}/stats`);
    }
}

class AnalyticsClient {
    constructor(private client: OpenSASEClient) { }

    async traffic(period = '24h'): Promise<any> {
        return this.client.request('GET', `/analytics/traffic?period=${period}`);
    }

    async threats(period = '24h'): Promise<any> {
        return this.client.request('GET', `/analytics/threats?period=${period}`);
    }
}

export default OpenSASEClient;
