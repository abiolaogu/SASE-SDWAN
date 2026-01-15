/**
 * OpenSASE TypeScript SDK
 * 
 * A comprehensive TypeScript/JavaScript SDK for the OpenSASE Platform API
 * 
 * @version 1.0.0
 * @license MIT
 */

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface OpenSASEConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
  headers?: Record<string, string>;
}

export interface RequestOptions {
  headers?: Record<string, string>;
  idempotencyKey?: string;
  timeout?: number;
}

export interface PaginationParams {
  page?: number;
  perPage?: number;
  limit?: number;
  cursor?: string;
}

export interface Pagination {
  page: number;
  perPage: number;
  total: number;
  totalPages: number;
}

export interface CursorPagination {
  hasMore: boolean;
  nextCursor: string | null;
  prevCursor: string | null;
}

export interface ListResponse<T> {
  data: T[];
  pagination: Pagination;
}

export interface CursorListResponse<T> {
  data: T[];
  pagination: CursorPagination;
}

export interface ApiError {
  code: string;
  message: string;
  requestId?: string;
  details?: ErrorDetail[];
  documentationUrl?: string;
}

export interface ErrorDetail {
  field: string;
  code: string;
  message: string;
}

// Identity Types
export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  profile: UserProfile;
  status: 'active' | 'inactive' | 'suspended' | 'pending';
  roles: string[];
  groups: GroupRef[];
  mfa: MFASettings;
  metadata: Record<string, any>;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UserProfile {
  firstName?: string;
  lastName?: string;
  displayName?: string;
  avatarUrl?: string;
  phone?: string;
  phoneVerified?: boolean;
  locale?: string;
  timezone?: string;
}

export interface GroupRef {
  id: string;
  name: string;
}

export interface MFASettings {
  enabled: boolean;
  methods: ('totp' | 'sms' | 'email' | 'webauthn')[];
}

export interface Group {
  id: string;
  name: string;
  description?: string;
  memberCount: number;
  roles: string[];
  createdAt: string;
  updatedAt: string;
}

export interface CreateUserParams {
  email: string;
  password?: string;
  profile?: Partial<UserProfile>;
  roles?: string[];
  groups?: string[];
  metadata?: Record<string, any>;
  sendWelcomeEmail?: boolean;
}

export interface UpdateUserParams {
  profile?: Partial<UserProfile>;
  status?: 'active' | 'inactive' | 'suspended';
  roles?: string[];
  metadata?: Record<string, any>;
}

export interface LoginParams {
  email: string;
  password: string;
  deviceInfo?: {
    deviceId?: string;
    deviceName?: string;
    os?: string;
    browser?: string;
  };
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  scope: string;
  user: User;
}

export interface MFARequiredResponse {
  mfaRequired: true;
  mfaToken: string;
  mfaMethods: string[];
  expiresIn: number;
}

// CRM Types
export interface Contact {
  id: string;
  firstName?: string;
  lastName?: string;
  email: string;
  phone?: string;
  mobile?: string;
  title?: string;
  department?: string;
  account?: { id: string; name: string };
  owner?: { id: string; name: string };
  leadSource?: string;
  leadStatus?: 'new' | 'contacted' | 'qualified' | 'unqualified';
  leadScore?: number;
  lifecycleStage?: string;
  address?: Address;
  socialProfiles?: { linkedin?: string; twitter?: string };
  tags?: string[];
  customFields?: Record<string, any>;
  lastActivityAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Address {
  street?: string;
  street2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
}

export interface CreateContactParams {
  firstName?: string;
  lastName?: string;
  email: string;
  phone?: string;
  mobile?: string;
  title?: string;
  companyName?: string;
  leadSource?: string;
  ownerId?: string;
  tags?: string[];
  customFields?: Record<string, any>;
}

export interface UpdateContactParams {
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  mobile?: string;
  title?: string;
  leadStatus?: 'new' | 'contacted' | 'qualified' | 'unqualified';
  ownerId?: string;
  tags?: string[];
  customFields?: Record<string, any>;
}

export interface Deal {
  id: string;
  name: string;
  amount: number;
  currency: string;
  pipeline?: { id: string; name: string };
  stage?: { id: string; name: string; probability: number };
  contact?: { id: string; name: string };
  account?: { id: string; name: string };
  owner?: { id: string; name: string };
  expectedCloseDate?: string;
  probability?: number;
  weightedValue?: number;
  dealType?: 'new_business' | 'renewal' | 'upsell' | 'cross_sell';
  leadSource?: string;
  competitors?: string[];
  customFields?: Record<string, any>;
  createdAt: string;
  updatedAt: string;
}

export interface CreateDealParams {
  name: string;
  amount: number;
  currency?: string;
  pipelineId: string;
  stageId: string;
  contactId?: string;
  accountId?: string;
  expectedCloseDate?: string;
  dealType?: 'new_business' | 'renewal' | 'upsell' | 'cross_sell';
  leadSource?: string;
  competitors?: string[];
  products?: { productId: string; quantity: number; price: number }[];
  customFields?: Record<string, any>;
}

// Payment Types
export interface PaymentIntent {
  id: string;
  amount: number;
  currency: string;
  status: PaymentIntentStatus;
  clientSecret?: string;
  customerId?: string;
  paymentMethodId?: string;
  paymentMethod?: PaymentMethod;
  captureMethod: 'automatic' | 'manual';
  amountCapturable?: number;
  amountReceived?: number;
  nextAction?: NextAction;
  charges?: Charge[];
  metadata?: Record<string, any>;
  receiptEmail?: string;
  createdAt: string;
}

export type PaymentIntentStatus = 
  | 'requires_payment_method'
  | 'requires_confirmation'
  | 'requires_action'
  | 'processing'
  | 'requires_capture'
  | 'canceled'
  | 'succeeded';

export interface PaymentMethod {
  id: string;
  type: string;
  card?: {
    brand: string;
    last4: string;
    expMonth: number;
    expYear: number;
  };
}

export interface NextAction {
  type: string;
  redirectToUrl?: {
    url: string;
    returnUrl: string;
  };
}

export interface Charge {
  id: string;
  amount: number;
  status: string;
  receiptUrl?: string;
}

export interface CreatePaymentIntentParams {
  amount: number;
  currency: string;
  customerId?: string;
  paymentMethodTypes?: string[];
  captureMethod?: 'automatic' | 'manual';
  metadata?: Record<string, any>;
  receiptEmail?: string;
}

export interface Subscription {
  id: string;
  customerId: string;
  plan: SubscriptionPlan;
  status: SubscriptionStatus;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  trialStart?: string;
  trialEnd?: string;
  cancelAtPeriodEnd: boolean;
  canceledAt?: string;
  cancelAt?: string;
  defaultPaymentMethodId?: string;
  latestInvoice?: { id: string; amountDue: number; status: string };
  metadata?: Record<string, any>;
  createdAt: string;
}

export interface SubscriptionPlan {
  id: string;
  name: string;
  amount: number;
  currency: string;
  interval: 'day' | 'week' | 'month' | 'year';
  intervalCount: number;
}

export type SubscriptionStatus = 
  | 'active'
  | 'past_due'
  | 'unpaid'
  | 'canceled'
  | 'incomplete'
  | 'incomplete_expired'
  | 'trialing'
  | 'paused';

export interface CreateSubscriptionParams {
  customerId: string;
  planId: string;
  paymentMethodId: string;
  trialPeriodDays?: number;
  billingCycleAnchor?: string;
  prorationBehavior?: 'create_prorations' | 'none' | 'always_invoice';
  metadata?: Record<string, any>;
}

export interface Refund {
  id: string;
  paymentIntentId: string;
  chargeId?: string;
  amount: number;
  currency: string;
  status: 'pending' | 'succeeded' | 'failed' | 'canceled';
  reason?: 'duplicate' | 'fraudulent' | 'requested_by_customer';
  metadata?: Record<string, any>;
  createdAt: string;
}

export interface CreateRefundParams {
  paymentIntentId: string;
  chargeId?: string;
  amount?: number;
  reason?: 'duplicate' | 'fraudulent' | 'requested_by_customer';
  metadata?: Record<string, any>;
}

// ============================================================================
// Error Classes
// ============================================================================

export class OpenSASEError extends Error {
  public readonly code: string;
  public readonly requestId?: string;
  public readonly statusCode: number;
  public readonly details?: ErrorDetail[];

  constructor(message: string, code: string, statusCode: number, requestId?: string, details?: ErrorDetail[]) {
    super(message);
    this.name = 'OpenSASEError';
    this.code = code;
    this.statusCode = statusCode;
    this.requestId = requestId;
    this.details = details;
  }
}

export class ValidationError extends OpenSASEError {
  constructor(message: string, requestId?: string, details?: ErrorDetail[]) {
    super(message, 'validation_error', 400, requestId, details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends OpenSASEError {
  constructor(message: string, requestId?: string) {
    super(message, 'unauthorized', 401, requestId);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends OpenSASEError {
  constructor(message: string, requestId?: string) {
    super(message, 'forbidden', 403, requestId);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends OpenSASEError {
  constructor(message: string, requestId?: string) {
    super(message, 'not_found', 404, requestId);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends OpenSASEError {
  constructor(message: string, requestId?: string) {
    super(message, 'conflict', 409, requestId);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends OpenSASEError {
  public readonly retryAfter: number;
  public readonly limit: number;
  public readonly remaining: number;

  constructor(message: string, retryAfter: number, limit: number, remaining: number, requestId?: string) {
    super(message, 'rate_limit_exceeded', 429, requestId);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    this.limit = limit;
    this.remaining = remaining;
  }
}

// ============================================================================
// HTTP Client
// ============================================================================

class HttpClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly retryDelay: number;
  private readonly defaultHeaders: Record<string, string>;

  constructor(config: OpenSASEConfig) {
    this.baseUrl = config.baseUrl || 'https://api.opensase.billyronks.io/v1';
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 30000;
    this.maxRetries = config.maxRetries || 3;
    this.retryDelay = config.retryDelay || 1000;
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
      ...config.headers,
    };
  }

  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private isRetryable(statusCode: number): boolean {
    return statusCode === 429 || statusCode >= 500;
  }

  private handleError(response: Response, body: any, requestId?: string): never {
    const error = body?.error || {};
    const message = error.message || 'An error occurred';
    const code = error.code || 'unknown_error';
    const details = error.details;

    switch (response.status) {
      case 400:
        throw new ValidationError(message, requestId, details);
      case 401:
        throw new AuthenticationError(message, requestId);
      case 403:
        throw new AuthorizationError(message, requestId);
      case 404:
        throw new NotFoundError(message, requestId);
      case 409:
        throw new ConflictError(message, requestId);
      case 429:
        const retryAfter = parseInt(response.headers.get('Retry-After') || '30', 10);
        const limit = parseInt(response.headers.get('X-RateLimit-Limit') || '0', 10);
        const remaining = parseInt(response.headers.get('X-RateLimit-Remaining') || '0', 10);
        throw new RateLimitError(message, retryAfter, limit, remaining, requestId);
      default:
        throw new OpenSASEError(message, code, response.status, requestId, details);
    }
  }

  private buildUrl(path: string, params?: Record<string, any>): string {
    const url = new URL(`${this.baseUrl}${path}`);
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          if (Array.isArray(value)) {
            url.searchParams.set(key, value.join(','));
          } else {
            url.searchParams.set(key, String(value));
          }
        }
      });
    }
    
    return url.toString();
  }

  private camelToSnake(str: string): string {
    return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
  }

  private snakeToCamel(str: string): string {
    return str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
  }

  private transformKeys(obj: any, transform: (key: string) => string): any {
    if (obj === null || obj === undefined) {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.transformKeys(item, transform));
    }
    
    if (typeof obj === 'object') {
      return Object.entries(obj).reduce((acc, [key, value]) => {
        acc[transform(key)] = this.transformKeys(value, transform);
        return acc;
      }, {} as Record<string, any>);
    }
    
    return obj;
  }

  private toSnakeCase(obj: any): any {
    return this.transformKeys(obj, this.camelToSnake);
  }

  private toCamelCase(obj: any): any {
    return this.transformKeys(obj, this.snakeToCamel);
  }

  async request<T>(
    method: string,
    path: string,
    options: {
      body?: any;
      params?: Record<string, any>;
      headers?: Record<string, string>;
      idempotencyKey?: string;
    } = {}
  ): Promise<T> {
    const url = this.buildUrl(path, options.params);
    const headers = {
      ...this.defaultHeaders,
      ...options.headers,
    };

    if (options.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    const fetchOptions: RequestInit = {
      method,
      headers,
    };

    if (options.body) {
      fetchOptions.body = JSON.stringify(this.toSnakeCase(options.body));
    }

    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        const response = await fetch(url, {
          ...fetchOptions,
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);

        const requestId = response.headers.get('X-Request-ID') || undefined;
        
        if (response.status === 204) {
          return undefined as T;
        }

        const body = await response.json();

        if (!response.ok) {
          if (this.isRetryable(response.status) && attempt < this.maxRetries) {
            const delay = response.status === 429
              ? parseInt(response.headers.get('Retry-After') || '1', 10) * 1000
              : this.retryDelay * Math.pow(2, attempt);
            await this.sleep(delay);
            continue;
          }
          this.handleError(response, body, requestId);
        }

        return this.toCamelCase(body.data || body) as T;
        
      } catch (error) {
        if (error instanceof OpenSASEError) {
          throw error;
        }
        
        lastError = error as Error;
        
        if (attempt < this.maxRetries) {
          await this.sleep(this.retryDelay * Math.pow(2, attempt));
          continue;
        }
      }
    }

    throw lastError || new Error('Request failed after retries');
  }

  get<T>(path: string, params?: Record<string, any>, options?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, { params, ...options });
  }

  post<T>(path: string, body?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, { body, ...options });
  }

  put<T>(path: string, body?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>('PUT', path, { body, ...options });
  }

  patch<T>(path: string, body?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>('PATCH', path, { body, ...options });
  }

  delete<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, options);
  }
}

// ============================================================================
// Service Classes
// ============================================================================

// Identity Service
class UsersService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams & {
    search?: string;
    status?: 'active' | 'inactive' | 'suspended' | 'pending';
    sort?: 'created_at' | 'name' | 'email';
    order?: 'asc' | 'desc';
  }): Promise<ListResponse<User>> {
    return this.client.get('/identity/users', params);
  }

  async create(params: CreateUserParams): Promise<User> {
    return this.client.post('/identity/users', params);
  }

  async get(userId: string): Promise<User> {
    return this.client.get(`/identity/users/${userId}`);
  }

  async update(userId: string, params: UpdateUserParams): Promise<User> {
    return this.client.patch(`/identity/users/${userId}`, params);
  }

  async delete(userId: string): Promise<void> {
    return this.client.delete(`/identity/users/${userId}`);
  }

  async *listAutoPaginate(params?: Parameters<UsersService['list']>[0]): AsyncGenerator<User> {
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await this.list({ ...params, page });
      
      for (const user of response.data) {
        yield user;
      }
      
      hasMore = page < response.pagination.totalPages;
      page++;
    }
  }
}

class AuthService {
  constructor(private readonly client: HttpClient) {}

  async login(params: LoginParams): Promise<LoginResponse | MFARequiredResponse> {
    return this.client.post('/identity/auth/login', params);
  }

  async verifyMFA(params: { mfaToken: string; method: string; code: string }): Promise<LoginResponse> {
    return this.client.post('/identity/auth/mfa/verify', params);
  }

  async refresh(refreshToken: string): Promise<LoginResponse> {
    return this.client.post('/identity/auth/refresh', { refreshToken });
  }

  async logout(params?: { refreshToken?: string; allDevices?: boolean }): Promise<void> {
    return this.client.post('/identity/auth/logout', params);
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    return this.client.post('/identity/auth/password/reset-request', { email });
  }

  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    return this.client.post('/identity/auth/password/reset', { token, newPassword });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
    return this.client.post('/identity/auth/password/change', { currentPassword, newPassword });
  }
}

class GroupsService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams): Promise<ListResponse<Group>> {
    return this.client.get('/identity/groups', params);
  }

  async create(params: { name: string; description?: string; roles?: string[] }): Promise<Group> {
    return this.client.post('/identity/groups', params);
  }

  async get(groupId: string): Promise<Group> {
    return this.client.get(`/identity/groups/${groupId}`);
  }

  async update(groupId: string, params: { name?: string; description?: string; roles?: string[] }): Promise<Group> {
    return this.client.patch(`/identity/groups/${groupId}`, params);
  }

  async delete(groupId: string): Promise<void> {
    return this.client.delete(`/identity/groups/${groupId}`);
  }

  async addMembers(groupId: string, userIds: string[]): Promise<{ added: number; alreadyMembers: number }> {
    return this.client.post(`/identity/groups/${groupId}/members`, { userIds });
  }

  async removeMembers(groupId: string, userIds: string[]): Promise<{ removed: number }> {
    return this.client.delete(`/identity/groups/${groupId}/members`, { body: { userIds } } as any);
  }
}

class IdentityService {
  public readonly users: UsersService;
  public readonly auth: AuthService;
  public readonly groups: GroupsService;

  constructor(client: HttpClient) {
    this.users = new UsersService(client);
    this.auth = new AuthService(client);
    this.groups = new GroupsService(client);
  }
}

// CRM Service
class ContactsService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams & {
    search?: string;
    status?: 'new' | 'contacted' | 'qualified' | 'unqualified';
    ownerId?: string;
    accountId?: string;
    tags?: string[];
    createdAfter?: string;
    sort?: 'lead_score' | 'created_at' | 'last_activity_at' | 'name';
    order?: 'asc' | 'desc';
  }): Promise<ListResponse<Contact>> {
    return this.client.get('/crm/contacts', params);
  }

  async create(params: CreateContactParams): Promise<Contact> {
    return this.client.post('/crm/contacts', params);
  }

  async get(contactId: string): Promise<Contact> {
    return this.client.get(`/crm/contacts/${contactId}`);
  }

  async update(contactId: string, params: UpdateContactParams): Promise<Contact> {
    return this.client.patch(`/crm/contacts/${contactId}`, params);
  }

  async delete(contactId: string): Promise<void> {
    return this.client.delete(`/crm/contacts/${contactId}`);
  }

  async get360View(contactId: string): Promise<any> {
    return this.client.get(`/crm/contacts/${contactId}/360`);
  }

  async *listAutoPaginate(params?: Parameters<ContactsService['list']>[0]): AsyncGenerator<Contact> {
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await this.list({ ...params, page });
      
      for (const contact of response.data) {
        yield contact;
      }
      
      hasMore = page < response.pagination.totalPages;
      page++;
    }
  }
}

class DealsService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams & {
    pipelineId?: string;
    stageId?: string;
    ownerId?: string;
    status?: 'open' | 'won' | 'lost';
    minAmount?: number;
    maxAmount?: number;
  }): Promise<ListResponse<Deal>> {
    return this.client.get('/crm/deals', params);
  }

  async create(params: CreateDealParams): Promise<Deal> {
    return this.client.post('/crm/deals', params);
  }

  async get(dealId: string): Promise<Deal> {
    return this.client.get(`/crm/deals/${dealId}`);
  }

  async update(dealId: string, params: Partial<CreateDealParams>): Promise<Deal> {
    return this.client.patch(`/crm/deals/${dealId}`, params);
  }

  async delete(dealId: string): Promise<void> {
    return this.client.delete(`/crm/deals/${dealId}`);
  }

  async moveToStage(dealId: string, stageId: string, note?: string): Promise<Deal> {
    return this.client.post(`/crm/deals/${dealId}/move`, { stageId, note });
  }
}

class PipelinesService {
  constructor(private readonly client: HttpClient) {}

  async list(): Promise<ListResponse<any>> {
    return this.client.get('/crm/pipelines');
  }

  async get(pipelineId: string): Promise<any> {
    return this.client.get(`/crm/pipelines/${pipelineId}`);
  }

  async getView(pipelineId: string, params?: {
    ownerId?: string;
    period?: 'this_month' | 'this_quarter' | 'this_year' | 'custom';
    startDate?: string;
    endDate?: string;
  }): Promise<any> {
    return this.client.get(`/crm/pipelines/${pipelineId}/view`, params);
  }
}

class CRMService {
  public readonly contacts: ContactsService;
  public readonly deals: DealsService;
  public readonly pipelines: PipelinesService;

  constructor(client: HttpClient) {
    this.contacts = new ContactsService(client);
    this.deals = new DealsService(client);
    this.pipelines = new PipelinesService(client);
  }
}

// Payments Service
class PaymentIntentsService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams & {
    customerId?: string;
    status?: PaymentIntentStatus;
    createdAfter?: string;
    createdBefore?: string;
  }): Promise<ListResponse<PaymentIntent>> {
    return this.client.get('/payments/intents', params);
  }

  async create(params: CreatePaymentIntentParams, options?: RequestOptions): Promise<PaymentIntent> {
    return this.client.post('/payments/intents', params, options);
  }

  async get(intentId: string): Promise<PaymentIntent> {
    return this.client.get(`/payments/intents/${intentId}`);
  }

  async confirm(intentId: string, params: {
    paymentMethodId: string;
    returnUrl?: string;
  }, options?: RequestOptions): Promise<PaymentIntent> {
    return this.client.post(`/payments/intents/${intentId}/confirm`, params, options);
  }

  async capture(intentId: string, amountToCapture?: number, options?: RequestOptions): Promise<PaymentIntent> {
    return this.client.post(`/payments/intents/${intentId}/capture`, { amountToCapture }, options);
  }

  async cancel(intentId: string, cancellationReason?: string): Promise<PaymentIntent> {
    return this.client.post(`/payments/intents/${intentId}/cancel`, { cancellationReason });
  }
}

class SubscriptionsService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams & {
    customerId?: string;
    status?: SubscriptionStatus;
    planId?: string;
  }): Promise<ListResponse<Subscription>> {
    return this.client.get('/payments/subscriptions', params);
  }

  async create(params: CreateSubscriptionParams, options?: RequestOptions): Promise<Subscription> {
    return this.client.post('/payments/subscriptions', params, options);
  }

  async get(subscriptionId: string): Promise<Subscription> {
    return this.client.get(`/payments/subscriptions/${subscriptionId}`);
  }

  async update(subscriptionId: string, params: {
    planId?: string;
    paymentMethodId?: string;
    prorationBehavior?: 'create_prorations' | 'none' | 'always_invoice';
    billingCycleAnchor?: 'now' | 'unchanged';
    metadata?: Record<string, any>;
  }): Promise<Subscription> {
    return this.client.patch(`/payments/subscriptions/${subscriptionId}`, params);
  }

  async cancel(subscriptionId: string, params?: {
    cancelAtPeriodEnd?: boolean;
    cancellationReason?: string;
  }): Promise<Subscription> {
    return this.client.post(`/payments/subscriptions/${subscriptionId}/cancel`, params);
  }

  async resume(subscriptionId: string): Promise<Subscription> {
    return this.client.post(`/payments/subscriptions/${subscriptionId}/resume`);
  }
}

class RefundsService {
  constructor(private readonly client: HttpClient) {}

  async list(params?: PaginationParams & {
    paymentIntentId?: string;
    chargeId?: string;
  }): Promise<ListResponse<Refund>> {
    return this.client.get('/payments/refunds', params);
  }

  async create(params: CreateRefundParams, options?: RequestOptions): Promise<Refund> {
    return this.client.post('/payments/refunds', params, options);
  }

  async get(refundId: string): Promise<Refund> {
    return this.client.get(`/payments/refunds/${refundId}`);
  }
}

class PaymentsService {
  public readonly intents: PaymentIntentsService;
  public readonly subscriptions: SubscriptionsService;
  public readonly refunds: RefundsService;

  constructor(client: HttpClient) {
    this.intents = new PaymentIntentsService(client);
    this.subscriptions = new SubscriptionsService(client);
    this.refunds = new RefundsService(client);
  }
}

// ============================================================================
// Main Client
// ============================================================================

export class OpenSASE {
  public readonly identity: IdentityService;
  public readonly crm: CRMService;
  public readonly payments: PaymentsService;
  
  // Error classes exposed as static properties
  static readonly OpenSASEError = OpenSASEError;
  static readonly ValidationError = ValidationError;
  static readonly AuthenticationError = AuthenticationError;
  static readonly AuthorizationError = AuthorizationError;
  static readonly NotFoundError = NotFoundError;
  static readonly ConflictError = ConflictError;
  static readonly RateLimitError = RateLimitError;

  constructor(config: OpenSASEConfig) {
    if (!config.apiKey) {
      throw new Error('API key is required');
    }

    const client = new HttpClient(config);
    
    this.identity = new IdentityService(client);
    this.crm = new CRMService(client);
    this.payments = new PaymentsService(client);
  }
}

// ============================================================================
// Webhook Utilities
// ============================================================================

export async function verifyWebhookSignature(
  payload: string | Buffer,
  signature: string,
  timestamp: string,
  secret: string,
  toleranceSeconds: number = 300
): Promise<boolean> {
  // Check timestamp tolerance
  const timestampMs = parseInt(timestamp, 10) * 1000;
  const now = Date.now();
  
  if (Math.abs(now - timestampMs) > toleranceSeconds * 1000) {
    throw new Error('Webhook timestamp outside tolerance');
  }
  
  // Import crypto for Node.js environment
  const crypto = await import('crypto');
  
  // Compute expected signature
  const payloadString = typeof payload === 'string' ? payload : payload.toString('utf-8');
  const signedPayload = `${timestamp}.${payloadString}`;
  
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
  
  // Parse and compare signatures
  const signatureParts = signature.split(',');
  
  for (const part of signatureParts) {
    const [version, sig] = part.split('=');
    if (version === 'v1') {
      return crypto.timingSafeEqual(
        Buffer.from(sig),
        Buffer.from(expectedSignature)
      );
    }
  }
  
  return false;
}

export interface WebhookEvent<T = any> {
  id: string;
  object: 'event';
  apiVersion: string;
  created: number;
  type: string;
  livemode: boolean;
  pendingWebhooks: number;
  request?: {
    id?: string;
    idempotencyKey?: string;
  };
  data: {
    object: T;
    previousAttributes?: Partial<T>;
  };
}

export function constructWebhookEvent<T = any>(
  payload: string | Buffer,
  signature: string,
  timestamp: string,
  secret: string
): WebhookEvent<T> {
  // Note: In production, call verifyWebhookSignature first
  const payloadString = typeof payload === 'string' ? payload : payload.toString('utf-8');
  return JSON.parse(payloadString);
}

// Default export
export default OpenSASE;
