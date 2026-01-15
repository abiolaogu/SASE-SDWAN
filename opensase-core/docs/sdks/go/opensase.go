// Package opensase provides a Go SDK for the OpenSASE Platform API.
//
// Usage:
//
//	import "github.com/billyronks/opensase-go"
//
//	client := opensase.NewClient("os_live_abc123...")
//
//	// Create a user
//	user, err := client.Identity.Users.Create(context.Background(), &opensase.CreateUserParams{
//	    Email: "john@example.com",
//	})
//
//	// List contacts
//	contacts, err := client.CRM.Contacts.List(context.Background(), &opensase.ListContactsParams{
//	    Search: opensase.String("acme"),
//	})
package opensase

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Version is the SDK version
	Version = "1.0.0"

	// DefaultBaseURL is the default API base URL
	DefaultBaseURL = "https://api.opensase.billyronks.io/v1"

	// DefaultTimeout is the default request timeout
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRetries is the default number of retries
	DefaultMaxRetries = 3
)

// Client is the OpenSASE API client
type Client struct {
	// Services
	Identity *IdentityService
	CRM      *CRMService
	Payments *PaymentsService

	// Configuration
	baseURL    string
	apiKey     string
	httpClient *http.Client
	maxRetries int
	retryDelay time.Duration
}

// ClientOption is a function that configures the client
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = strings.TrimSuffix(url, "/")
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithTimeout sets the request timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithMaxRetries sets the maximum number of retries
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *Client) {
		c.maxRetries = maxRetries
	}
}

// WithRetryDelay sets the base delay between retries
func WithRetryDelay(delay time.Duration) ClientOption {
	return func(c *Client) {
		c.retryDelay = delay
	}
}

// NewClient creates a new OpenSASE API client
func NewClient(apiKey string, opts ...ClientOption) *Client {
	if apiKey == "" {
		panic("opensase: API key is required")
	}

	c := &Client{
		baseURL: DefaultBaseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		maxRetries: DefaultMaxRetries,
		retryDelay: time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Initialize services
	c.Identity = &IdentityService{client: c}
	c.CRM = &CRMService{client: c}
	c.Payments = &PaymentsService{client: c}

	return c
}

// Error represents an API error
type Error struct {
	Code       string        `json:"code"`
	Message    string        `json:"message"`
	RequestID  string        `json:"request_id,omitempty"`
	StatusCode int           `json:"-"`
	Details    []ErrorDetail `json:"details,omitempty"`
}

// ErrorDetail provides additional error information
type ErrorDetail struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// IsValidationError returns true if this is a validation error
func (e *Error) IsValidationError() bool {
	return e.StatusCode == 400
}

// IsAuthenticationError returns true if this is an authentication error
func (e *Error) IsAuthenticationError() bool {
	return e.StatusCode == 401
}

// IsAuthorizationError returns true if this is an authorization error
func (e *Error) IsAuthorizationError() bool {
	return e.StatusCode == 403
}

// IsNotFoundError returns true if this is a not found error
func (e *Error) IsNotFoundError() bool {
	return e.StatusCode == 404
}

// IsRateLimitError returns true if this is a rate limit error
func (e *Error) IsRateLimitError() bool {
	return e.StatusCode == 429
}

// RateLimitError contains rate limit specific information
type RateLimitError struct {
	*Error
	RetryAfter int
	Limit      int
	Remaining  int
}

// Pagination contains pagination information
type Pagination struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// CursorPagination contains cursor-based pagination information
type CursorPagination struct {
	HasMore    bool    `json:"has_more"`
	NextCursor *string `json:"next_cursor,omitempty"`
	PrevCursor *string `json:"prev_cursor,omitempty"`
}

// ListParams contains common list parameters
type ListParams struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
}

// RequestOptions contains options for individual requests
type RequestOptions struct {
	IdempotencyKey string
	Headers        map[string]string
}

// Helper functions for optional parameters
func String(v string) *string { return &v }
func Int(v int) *int          { return &v }
func Int64(v int64) *int64    { return &v }
func Bool(v bool) *bool       { return &v }
func Float64(v float64) *float64 { return &v }

// request makes an HTTP request to the API
func (c *Client) request(ctx context.Context, method, path string, body interface{}, opts *RequestOptions) (json.RawMessage, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "opensase-go/"+Version)

		if opts != nil {
			if opts.IdempotencyKey != "" {
				req.Header.Set("Idempotency-Key", opts.IdempotencyKey)
			}
			for k, v := range opts.Headers {
				req.Header.Set(k, v)
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.maxRetries {
				time.Sleep(c.retryDelay * time.Duration(1<<attempt))
				continue
			}
			return nil, err
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		requestID := resp.Header.Get("X-Request-ID")

		if resp.StatusCode == 204 {
			return nil, nil
		}

		if resp.StatusCode >= 400 {
			if isRetryable(resp.StatusCode) && attempt < c.maxRetries {
				delay := c.retryDelay * time.Duration(1<<attempt)
				if resp.StatusCode == 429 {
					if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
						if seconds, err := strconv.Atoi(retryAfter); err == nil {
							delay = time.Duration(seconds) * time.Second
						}
					}
				}
				time.Sleep(delay)
				continue
			}

			return nil, parseError(respBody, resp.StatusCode, requestID, resp.Header)
		}

		var response struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(respBody, &response); err != nil {
			// If it doesn't have a data wrapper, return the raw body
			return respBody, nil
		}

		if response.Data != nil {
			return response.Data, nil
		}
		return respBody, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("request failed after %d retries", c.maxRetries)
}

func isRetryable(statusCode int) bool {
	return statusCode == 429 || statusCode >= 500
}

func parseError(body []byte, statusCode int, requestID string, headers http.Header) error {
	var errorResponse struct {
		Error struct {
			Code    string        `json:"code"`
			Message string        `json:"message"`
			Details []ErrorDetail `json:"details,omitempty"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &errorResponse); err != nil {
		return &Error{
			Code:       "unknown_error",
			Message:    string(body),
			StatusCode: statusCode,
			RequestID:  requestID,
		}
	}

	apiErr := &Error{
		Code:       errorResponse.Error.Code,
		Message:    errorResponse.Error.Message,
		StatusCode: statusCode,
		RequestID:  requestID,
		Details:    errorResponse.Error.Details,
	}

	if statusCode == 429 {
		retryAfter, _ := strconv.Atoi(headers.Get("Retry-After"))
		limit, _ := strconv.Atoi(headers.Get("X-RateLimit-Limit"))
		remaining, _ := strconv.Atoi(headers.Get("X-RateLimit-Remaining"))

		return &RateLimitError{
			Error:      apiErr,
			RetryAfter: retryAfter,
			Limit:      limit,
			Remaining:  remaining,
		}
	}

	return apiErr
}

func (c *Client) get(ctx context.Context, path string, params url.Values, opts *RequestOptions) (json.RawMessage, error) {
	if len(params) > 0 {
		path = path + "?" + params.Encode()
	}
	return c.request(ctx, "GET", path, nil, opts)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, opts *RequestOptions) (json.RawMessage, error) {
	return c.request(ctx, "POST", path, body, opts)
}

func (c *Client) patch(ctx context.Context, path string, body interface{}, opts *RequestOptions) (json.RawMessage, error) {
	return c.request(ctx, "PATCH", path, body, opts)
}

func (c *Client) delete(ctx context.Context, path string, opts *RequestOptions) error {
	_, err := c.request(ctx, "DELETE", path, nil, opts)
	return err
}

// =============================================================================
// Identity Service
// =============================================================================

// IdentityService provides access to identity management APIs
type IdentityService struct {
	client *Client
	Users  *UsersService
	Auth   *AuthService
	Groups *GroupsService
}

// UsersService provides access to user management APIs
type UsersService struct {
	client *Client
}

// User represents a user
type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Profile       *UserProfile           `json:"profile,omitempty"`
	Status        string                 `json:"status"`
	Roles         []string               `json:"roles"`
	Groups        []GroupRef             `json:"groups,omitempty"`
	MFA           *MFASettings           `json:"mfa,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	LastLoginAt   *time.Time             `json:"last_login_at,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// UserProfile contains user profile information
type UserProfile struct {
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
	AvatarURL     string `json:"avatar_url,omitempty"`
	Phone         string `json:"phone,omitempty"`
	PhoneVerified bool   `json:"phone_verified,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Timezone      string `json:"timezone,omitempty"`
}

// GroupRef is a reference to a group
type GroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MFASettings contains MFA configuration
type MFASettings struct {
	Enabled bool     `json:"enabled"`
	Methods []string `json:"methods"`
}

// CreateUserParams contains parameters for creating a user
type CreateUserParams struct {
	Email            string                 `json:"email"`
	Password         string                 `json:"password,omitempty"`
	Profile          *UserProfile           `json:"profile,omitempty"`
	Roles            []string               `json:"roles,omitempty"`
	Groups           []string               `json:"groups,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	SendWelcomeEmail bool                   `json:"send_welcome_email,omitempty"`
}

// UpdateUserParams contains parameters for updating a user
type UpdateUserParams struct {
	Profile  *UserProfile           `json:"profile,omitempty"`
	Status   *string                `json:"status,omitempty"`
	Roles    []string               `json:"roles,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ListUsersParams contains parameters for listing users
type ListUsersParams struct {
	Page    int     `json:"page,omitempty"`
	PerPage int     `json:"per_page,omitempty"`
	Search  *string `json:"search,omitempty"`
	Status  *string `json:"status,omitempty"`
	Sort    *string `json:"sort,omitempty"`
	Order   *string `json:"order,omitempty"`
}

// UserListResponse contains a list of users with pagination
type UserListResponse struct {
	Data       []User     `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// List retrieves all users with pagination
func (s *UsersService) List(ctx context.Context, params *ListUsersParams) (*UserListResponse, error) {
	v := url.Values{}
	if params != nil {
		if params.Page > 0 {
			v.Set("page", strconv.Itoa(params.Page))
		}
		if params.PerPage > 0 {
			v.Set("per_page", strconv.Itoa(params.PerPage))
		}
		if params.Search != nil {
			v.Set("search", *params.Search)
		}
		if params.Status != nil {
			v.Set("status", *params.Status)
		}
		if params.Sort != nil {
			v.Set("sort", *params.Sort)
		}
		if params.Order != nil {
			v.Set("order", *params.Order)
		}
	}

	data, err := s.client.get(ctx, "/identity/users", v, nil)
	if err != nil {
		return nil, err
	}

	var response UserListResponse
	if err := json.Unmarshal(data, &response); err != nil {
		// Try unmarshaling as array
		var users []User
		if err := json.Unmarshal(data, &users); err != nil {
			return nil, err
		}
		response.Data = users
	}

	return &response, nil
}

// Create creates a new user
func (s *UsersService) Create(ctx context.Context, params *CreateUserParams) (*User, error) {
	data, err := s.client.post(ctx, "/identity/users", params, nil)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Get retrieves a user by ID
func (s *UsersService) Get(ctx context.Context, userID string) (*User, error) {
	data, err := s.client.get(ctx, "/identity/users/"+userID, nil, nil)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Update updates a user
func (s *UsersService) Update(ctx context.Context, userID string, params *UpdateUserParams) (*User, error) {
	data, err := s.client.patch(ctx, "/identity/users/"+userID, params, nil)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Delete deletes a user
func (s *UsersService) Delete(ctx context.Context, userID string) error {
	return s.client.delete(ctx, "/identity/users/"+userID, nil)
}

// AuthService provides access to authentication APIs
type AuthService struct {
	client *Client
}

// LoginParams contains login parameters
type LoginParams struct {
	Email      string                 `json:"email"`
	Password   string                 `json:"password"`
	DeviceInfo map[string]interface{} `json:"device_info,omitempty"`
}

// LoginResponse contains login response
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	User         *User  `json:"user,omitempty"`

	// MFA fields (if MFA is required)
	MFARequired bool     `json:"mfa_required,omitempty"`
	MFAToken    string   `json:"mfa_token,omitempty"`
	MFAMethods  []string `json:"mfa_methods,omitempty"`
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, params *LoginParams) (*LoginResponse, error) {
	data, err := s.client.post(ctx, "/identity/auth/login", params, nil)
	if err != nil {
		return nil, err
	}

	var response LoginResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// VerifyMFA verifies MFA code
func (s *AuthService) VerifyMFA(ctx context.Context, mfaToken, method, code string) (*LoginResponse, error) {
	params := map[string]string{
		"mfa_token": mfaToken,
		"method":    method,
		"code":      code,
	}

	data, err := s.client.post(ctx, "/identity/auth/mfa/verify", params, nil)
	if err != nil {
		return nil, err
	}

	var response LoginResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Refresh refreshes an access token
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	params := map[string]string{
		"refresh_token": refreshToken,
	}

	data, err := s.client.post(ctx, "/identity/auth/refresh", params, nil)
	if err != nil {
		return nil, err
	}

	var response LoginResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Logout logs out the current session
func (s *AuthService) Logout(ctx context.Context, refreshToken string, allDevices bool) error {
	params := map[string]interface{}{
		"refresh_token": refreshToken,
		"all_devices":   allDevices,
	}

	_, err := s.client.post(ctx, "/identity/auth/logout", params, nil)
	return err
}

// GroupsService provides access to group management APIs
type GroupsService struct {
	client *Client
}

// Group represents a group
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	MemberCount int       `json:"member_count"`
	Roles       []string  `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateGroupParams contains parameters for creating a group
type CreateGroupParams struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Roles       []string `json:"roles,omitempty"`
}

// Create creates a new group
func (s *GroupsService) Create(ctx context.Context, params *CreateGroupParams) (*Group, error) {
	data, err := s.client.post(ctx, "/identity/groups", params, nil)
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return nil, err
	}

	return &group, nil
}

// AddMembers adds members to a group
func (s *GroupsService) AddMembers(ctx context.Context, groupID string, userIDs []string) error {
	params := map[string][]string{
		"user_ids": userIDs,
	}

	_, err := s.client.post(ctx, "/identity/groups/"+groupID+"/members", params, nil)
	return err
}

// =============================================================================
// CRM Service
// =============================================================================

// CRMService provides access to CRM APIs
type CRMService struct {
	client    *Client
	Contacts  *ContactsService
	Deals     *DealsService
	Pipelines *PipelinesService
}

// ContactsService provides access to contact APIs
type ContactsService struct {
	client *Client
}

// Contact represents a contact
type Contact struct {
	ID             string                 `json:"id"`
	FirstName      string                 `json:"first_name,omitempty"`
	LastName       string                 `json:"last_name,omitempty"`
	Email          string                 `json:"email"`
	Phone          string                 `json:"phone,omitempty"`
	Mobile         string                 `json:"mobile,omitempty"`
	Title          string                 `json:"title,omitempty"`
	Department     string                 `json:"department,omitempty"`
	Account        *AccountRef            `json:"account,omitempty"`
	Owner          *OwnerRef              `json:"owner,omitempty"`
	LeadSource     string                 `json:"lead_source,omitempty"`
	LeadStatus     string                 `json:"lead_status,omitempty"`
	LeadScore      int                    `json:"lead_score,omitempty"`
	LifecycleStage string                 `json:"lifecycle_stage,omitempty"`
	Address        *Address               `json:"address,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
	CustomFields   map[string]interface{} `json:"custom_fields,omitempty"`
	LastActivityAt *time.Time             `json:"last_activity_at,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// AccountRef is a reference to an account
type AccountRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// OwnerRef is a reference to an owner
type OwnerRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Address represents an address
type Address struct {
	Street     string `json:"street,omitempty"`
	Street2    string `json:"street2,omitempty"`
	City       string `json:"city,omitempty"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

// CreateContactParams contains parameters for creating a contact
type CreateContactParams struct {
	Email        string                 `json:"email"`
	FirstName    string                 `json:"first_name,omitempty"`
	LastName     string                 `json:"last_name,omitempty"`
	Phone        string                 `json:"phone,omitempty"`
	Mobile       string                 `json:"mobile,omitempty"`
	Title        string                 `json:"title,omitempty"`
	CompanyName  string                 `json:"company_name,omitempty"`
	LeadSource   string                 `json:"lead_source,omitempty"`
	OwnerID      string                 `json:"owner_id,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}

// ListContactsParams contains parameters for listing contacts
type ListContactsParams struct {
	Page         int      `json:"page,omitempty"`
	PerPage      int      `json:"per_page,omitempty"`
	Search       *string  `json:"search,omitempty"`
	Status       *string  `json:"status,omitempty"`
	OwnerID      *string  `json:"owner_id,omitempty"`
	AccountID    *string  `json:"account_id,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	CreatedAfter *string  `json:"created_after,omitempty"`
	Sort         *string  `json:"sort,omitempty"`
	Order        *string  `json:"order,omitempty"`
}

// ContactListResponse contains a list of contacts with pagination
type ContactListResponse struct {
	Data       []Contact  `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// List retrieves all contacts with pagination
func (s *ContactsService) List(ctx context.Context, params *ListContactsParams) (*ContactListResponse, error) {
	v := url.Values{}
	if params != nil {
		if params.Page > 0 {
			v.Set("page", strconv.Itoa(params.Page))
		}
		if params.PerPage > 0 {
			v.Set("per_page", strconv.Itoa(params.PerPage))
		}
		if params.Search != nil {
			v.Set("search", *params.Search)
		}
		if params.Status != nil {
			v.Set("status", *params.Status)
		}
		if params.OwnerID != nil {
			v.Set("owner_id", *params.OwnerID)
		}
		if params.Sort != nil {
			v.Set("sort", *params.Sort)
		}
		if params.Order != nil {
			v.Set("order", *params.Order)
		}
	}

	data, err := s.client.get(ctx, "/crm/contacts", v, nil)
	if err != nil {
		return nil, err
	}

	var response ContactListResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Create creates a new contact
func (s *ContactsService) Create(ctx context.Context, params *CreateContactParams) (*Contact, error) {
	data, err := s.client.post(ctx, "/crm/contacts", params, nil)
	if err != nil {
		return nil, err
	}

	var contact Contact
	if err := json.Unmarshal(data, &contact); err != nil {
		return nil, err
	}

	return &contact, nil
}

// Get retrieves a contact by ID
func (s *ContactsService) Get(ctx context.Context, contactID string) (*Contact, error) {
	data, err := s.client.get(ctx, "/crm/contacts/"+contactID, nil, nil)
	if err != nil {
		return nil, err
	}

	var contact Contact
	if err := json.Unmarshal(data, &contact); err != nil {
		return nil, err
	}

	return &contact, nil
}

// Delete deletes a contact
func (s *ContactsService) Delete(ctx context.Context, contactID string) error {
	return s.client.delete(ctx, "/crm/contacts/"+contactID, nil)
}

// DealsService provides access to deal APIs
type DealsService struct {
	client *Client
}

// Deal represents a deal
type Deal struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Amount            float64                `json:"amount"`
	Currency          string                 `json:"currency"`
	Pipeline          *PipelineRef           `json:"pipeline,omitempty"`
	Stage             *StageRef              `json:"stage,omitempty"`
	Contact           *ContactRef            `json:"contact,omitempty"`
	Account           *AccountRef            `json:"account,omitempty"`
	Owner             *OwnerRef              `json:"owner,omitempty"`
	ExpectedCloseDate *string                `json:"expected_close_date,omitempty"`
	Probability       float64                `json:"probability,omitempty"`
	WeightedValue     float64                `json:"weighted_value,omitempty"`
	DealType          string                 `json:"deal_type,omitempty"`
	LeadSource        string                 `json:"lead_source,omitempty"`
	Competitors       []string               `json:"competitors,omitempty"`
	CustomFields      map[string]interface{} `json:"custom_fields,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// PipelineRef is a reference to a pipeline
type PipelineRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// StageRef is a reference to a stage
type StageRef struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
}

// ContactRef is a reference to a contact
type ContactRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CreateDealParams contains parameters for creating a deal
type CreateDealParams struct {
	Name              string                 `json:"name"`
	Amount            float64                `json:"amount"`
	Currency          string                 `json:"currency,omitempty"`
	PipelineID        string                 `json:"pipeline_id"`
	StageID           string                 `json:"stage_id"`
	ContactID         string                 `json:"contact_id,omitempty"`
	AccountID         string                 `json:"account_id,omitempty"`
	ExpectedCloseDate string                 `json:"expected_close_date,omitempty"`
	DealType          string                 `json:"deal_type,omitempty"`
	LeadSource        string                 `json:"lead_source,omitempty"`
	Competitors       []string               `json:"competitors,omitempty"`
	CustomFields      map[string]interface{} `json:"custom_fields,omitempty"`
}

// Create creates a new deal
func (s *DealsService) Create(ctx context.Context, params *CreateDealParams) (*Deal, error) {
	data, err := s.client.post(ctx, "/crm/deals", params, nil)
	if err != nil {
		return nil, err
	}

	var deal Deal
	if err := json.Unmarshal(data, &deal); err != nil {
		return nil, err
	}

	return &deal, nil
}

// MoveToStage moves a deal to a different stage
func (s *DealsService) MoveToStage(ctx context.Context, dealID, stageID string, note *string) (*Deal, error) {
	params := map[string]interface{}{
		"stage_id": stageID,
	}
	if note != nil {
		params["note"] = *note
	}

	data, err := s.client.post(ctx, "/crm/deals/"+dealID+"/move", params, nil)
	if err != nil {
		return nil, err
	}

	var deal Deal
	if err := json.Unmarshal(data, &deal); err != nil {
		return nil, err
	}

	return &deal, nil
}

// PipelinesService provides access to pipeline APIs
type PipelinesService struct {
	client *Client
}

// =============================================================================
// Payments Service
// =============================================================================

// PaymentsService provides access to payment APIs
type PaymentsService struct {
	client        *Client
	Intents       *PaymentIntentsService
	Subscriptions *SubscriptionsService
	Refunds       *RefundsService
}

// PaymentIntentsService provides access to payment intent APIs
type PaymentIntentsService struct {
	client *Client
}

// PaymentIntent represents a payment intent
type PaymentIntent struct {
	ID               string                 `json:"id"`
	Amount           int64                  `json:"amount"`
	Currency         string                 `json:"currency"`
	Status           string                 `json:"status"`
	ClientSecret     string                 `json:"client_secret,omitempty"`
	CustomerID       string                 `json:"customer_id,omitempty"`
	PaymentMethodID  string                 `json:"payment_method_id,omitempty"`
	PaymentMethod    *PaymentMethod         `json:"payment_method,omitempty"`
	CaptureMethod    string                 `json:"capture_method"`
	AmountCapturable int64                  `json:"amount_capturable,omitempty"`
	AmountReceived   int64                  `json:"amount_received,omitempty"`
	NextAction       *NextAction            `json:"next_action,omitempty"`
	Charges          []Charge               `json:"charges,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	ReceiptEmail     string                 `json:"receipt_email,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

// PaymentMethod represents a payment method
type PaymentMethod struct {
	ID   string      `json:"id"`
	Type string      `json:"type"`
	Card *CardDetail `json:"card,omitempty"`
}

// CardDetail contains card details
type CardDetail struct {
	Brand    string `json:"brand"`
	Last4    string `json:"last4"`
	ExpMonth int    `json:"exp_month"`
	ExpYear  int    `json:"exp_year"`
}

// NextAction contains information about required next actions
type NextAction struct {
	Type          string         `json:"type"`
	RedirectToURL *RedirectToURL `json:"redirect_to_url,omitempty"`
}

// RedirectToURL contains redirect information
type RedirectToURL struct {
	URL       string `json:"url"`
	ReturnURL string `json:"return_url"`
}

// Charge represents a charge
type Charge struct {
	ID         string `json:"id"`
	Amount     int64  `json:"amount"`
	Status     string `json:"status"`
	ReceiptURL string `json:"receipt_url,omitempty"`
}

// CreatePaymentIntentParams contains parameters for creating a payment intent
type CreatePaymentIntentParams struct {
	Amount             int64                  `json:"amount"`
	Currency           string                 `json:"currency"`
	CustomerID         string                 `json:"customer_id,omitempty"`
	PaymentMethodTypes []string               `json:"payment_method_types,omitempty"`
	CaptureMethod      string                 `json:"capture_method,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	ReceiptEmail       string                 `json:"receipt_email,omitempty"`
}

// Create creates a new payment intent
func (s *PaymentIntentsService) Create(ctx context.Context, params *CreatePaymentIntentParams, opts *RequestOptions) (*PaymentIntent, error) {
	data, err := s.client.post(ctx, "/payments/intents", params, opts)
	if err != nil {
		return nil, err
	}

	var intent PaymentIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, err
	}

	return &intent, nil
}

// Get retrieves a payment intent by ID
func (s *PaymentIntentsService) Get(ctx context.Context, intentID string) (*PaymentIntent, error) {
	data, err := s.client.get(ctx, "/payments/intents/"+intentID, nil, nil)
	if err != nil {
		return nil, err
	}

	var intent PaymentIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, err
	}

	return &intent, nil
}

// Confirm confirms a payment intent
func (s *PaymentIntentsService) Confirm(ctx context.Context, intentID, paymentMethodID string, returnURL *string, opts *RequestOptions) (*PaymentIntent, error) {
	params := map[string]interface{}{
		"payment_method_id": paymentMethodID,
	}
	if returnURL != nil {
		params["return_url"] = *returnURL
	}

	data, err := s.client.post(ctx, "/payments/intents/"+intentID+"/confirm", params, opts)
	if err != nil {
		return nil, err
	}

	var intent PaymentIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, err
	}

	return &intent, nil
}

// Capture captures a payment intent
func (s *PaymentIntentsService) Capture(ctx context.Context, intentID string, amountToCapture *int64, opts *RequestOptions) (*PaymentIntent, error) {
	params := map[string]interface{}{}
	if amountToCapture != nil {
		params["amount_to_capture"] = *amountToCapture
	}

	data, err := s.client.post(ctx, "/payments/intents/"+intentID+"/capture", params, opts)
	if err != nil {
		return nil, err
	}

	var intent PaymentIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, err
	}

	return &intent, nil
}

// Cancel cancels a payment intent
func (s *PaymentIntentsService) Cancel(ctx context.Context, intentID string, reason *string) (*PaymentIntent, error) {
	params := map[string]interface{}{}
	if reason != nil {
		params["cancellation_reason"] = *reason
	}

	data, err := s.client.post(ctx, "/payments/intents/"+intentID+"/cancel", params, nil)
	if err != nil {
		return nil, err
	}

	var intent PaymentIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, err
	}

	return &intent, nil
}

// SubscriptionsService provides access to subscription APIs
type SubscriptionsService struct {
	client *Client
}

// Subscription represents a subscription
type Subscription struct {
	ID                     string                 `json:"id"`
	CustomerID             string                 `json:"customer_id"`
	Plan                   *SubscriptionPlan      `json:"plan"`
	Status                 string                 `json:"status"`
	CurrentPeriodStart     time.Time              `json:"current_period_start"`
	CurrentPeriodEnd       time.Time              `json:"current_period_end"`
	TrialStart             *time.Time             `json:"trial_start,omitempty"`
	TrialEnd               *time.Time             `json:"trial_end,omitempty"`
	CancelAtPeriodEnd      bool                   `json:"cancel_at_period_end"`
	CanceledAt             *time.Time             `json:"canceled_at,omitempty"`
	CancelAt               *time.Time             `json:"cancel_at,omitempty"`
	DefaultPaymentMethodID string                 `json:"default_payment_method_id,omitempty"`
	LatestInvoice          *InvoiceRef            `json:"latest_invoice,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt              time.Time              `json:"created_at"`
}

// SubscriptionPlan represents a subscription plan
type SubscriptionPlan struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Amount        int64  `json:"amount"`
	Currency      string `json:"currency"`
	Interval      string `json:"interval"`
	IntervalCount int    `json:"interval_count"`
}

// InvoiceRef is a reference to an invoice
type InvoiceRef struct {
	ID        string `json:"id"`
	AmountDue int64  `json:"amount_due"`
	Status    string `json:"status"`
}

// CreateSubscriptionParams contains parameters for creating a subscription
type CreateSubscriptionParams struct {
	CustomerID         string                 `json:"customer_id"`
	PlanID             string                 `json:"plan_id"`
	PaymentMethodID    string                 `json:"payment_method_id"`
	TrialPeriodDays    *int                   `json:"trial_period_days,omitempty"`
	BillingCycleAnchor *string                `json:"billing_cycle_anchor,omitempty"`
	ProrationBehavior  string                 `json:"proration_behavior,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

// Create creates a new subscription
func (s *SubscriptionsService) Create(ctx context.Context, params *CreateSubscriptionParams, opts *RequestOptions) (*Subscription, error) {
	data, err := s.client.post(ctx, "/payments/subscriptions", params, opts)
	if err != nil {
		return nil, err
	}

	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return nil, err
	}

	return &sub, nil
}

// Cancel cancels a subscription
func (s *SubscriptionsService) Cancel(ctx context.Context, subscriptionID string, cancelAtPeriodEnd bool, reason *string) (*Subscription, error) {
	params := map[string]interface{}{
		"cancel_at_period_end": cancelAtPeriodEnd,
	}
	if reason != nil {
		params["cancellation_reason"] = *reason
	}

	data, err := s.client.post(ctx, "/payments/subscriptions/"+subscriptionID+"/cancel", params, nil)
	if err != nil {
		return nil, err
	}

	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return nil, err
	}

	return &sub, nil
}

// RefundsService provides access to refund APIs
type RefundsService struct {
	client *Client
}

// Refund represents a refund
type Refund struct {
	ID              string                 `json:"id"`
	PaymentIntentID string                 `json:"payment_intent_id"`
	ChargeID        string                 `json:"charge_id,omitempty"`
	Amount          int64                  `json:"amount"`
	Currency        string                 `json:"currency"`
	Status          string                 `json:"status"`
	Reason          string                 `json:"reason,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}

// CreateRefundParams contains parameters for creating a refund
type CreateRefundParams struct {
	PaymentIntentID string                 `json:"payment_intent_id"`
	ChargeID        string                 `json:"charge_id,omitempty"`
	Amount          *int64                 `json:"amount,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Create creates a new refund
func (s *RefundsService) Create(ctx context.Context, params *CreateRefundParams, opts *RequestOptions) (*Refund, error) {
	data, err := s.client.post(ctx, "/payments/refunds", params, opts)
	if err != nil {
		return nil, err
	}

	var refund Refund
	if err := json.Unmarshal(data, &refund); err != nil {
		return nil, err
	}

	return &refund, nil
}

// =============================================================================
// Webhook Utilities
// =============================================================================

// VerifyWebhookSignature verifies the webhook signature
func VerifyWebhookSignature(payload []byte, signature, timestamp, secret string, tolerance int64) (bool, error) {
	// Check timestamp tolerance
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false, fmt.Errorf("invalid timestamp: %w", err)
	}

	now := time.Now().Unix()
	if abs(now-ts) > tolerance {
		return false, fmt.Errorf("timestamp outside tolerance")
	}

	// Compute expected signature
	signedPayload := fmt.Sprintf("%s.%s", timestamp, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	// Parse and compare signatures
	for _, part := range strings.Split(signature, ",") {
		parts := strings.Split(part, "=")
		if len(parts) == 2 && parts[0] == "v1" {
			return hmac.Equal([]byte(parts[1]), []byte(expectedSig)), nil
		}
	}

	return false, nil
}

// WebhookEvent represents a webhook event
type WebhookEvent struct {
	ID              string                 `json:"id"`
	Object          string                 `json:"object"`
	APIVersion      string                 `json:"api_version"`
	Created         int64                  `json:"created"`
	Type            string                 `json:"type"`
	Livemode        bool                   `json:"livemode"`
	PendingWebhooks int                    `json:"pending_webhooks"`
	Request         *WebhookRequest        `json:"request,omitempty"`
	Data            map[string]interface{} `json:"data"`
}

// WebhookRequest contains request information
type WebhookRequest struct {
	ID             string `json:"id,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// ConstructWebhookEvent constructs and verifies a webhook event
func ConstructWebhookEvent(payload []byte, signature, timestamp, secret string) (*WebhookEvent, error) {
	valid, err := VerifyWebhookSignature(payload, signature, timestamp, secret, 300)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid webhook signature")
	}

	var event WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, err
	}

	return &event, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// Initialize services when IdentityService is accessed
func init() {
	// Services are initialized in NewClient
}
