package authsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kerimovok/go-pkg-utils/hmac"
)

// Config holds configuration for the auth service client
type Config struct {
	BaseURL    string        // Auth service base URL (e.g., "http://localhost:3001")
	HMACSecret string        // Shared HMAC secret for authentication
	Timeout    time.Duration // Request timeout (default: 10 seconds)
}

// Client wraps the HMAC client for auth-service communication
type Client struct {
	client *hmac.Client
}

// APIError represents an error returned by the auth service API
type APIError struct {
	StatusCode int    // HTTP status code
	Message    string // Error message from the API response
	Body       string // Raw response body (for debugging)
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("auth service returned status %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("auth service returned status %d: %s", e.StatusCode, e.Body)
}

// IsAPIError checks if an error is an APIError and returns it
func IsAPIError(err error) (*APIError, bool) {
	if err == nil {
		return nil, false
	}
	if apiErr, ok := err.(*APIError); ok {
		return apiErr, true
	}
	return nil, false
}

// parseErrorResponse parses an error response from the auth service
func parseErrorResponse(statusCode int, body []byte) *APIError {
	var errorResp struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
		Status  int    `json:"status"`
		Error   string `json:"error"`
	}

	bodyStr := string(body)
	if err := json.Unmarshal(body, &errorResp); err == nil && (errorResp.Message != "" || errorResp.Error != "") {
		// Prefer the detailed error field if available, otherwise use message
		errMessage := errorResp.Error
		if errMessage == "" {
			errMessage = errorResp.Message
		}
		return &APIError{
			StatusCode: statusCode,
			Message:    errMessage,
			Body:       bodyStr,
		}
	}

	// If JSON parsing failed, return the raw body as message
	return &APIError{
		StatusCode: statusCode,
		Message:    bodyStr,
		Body:       bodyStr,
	}
}

// NewClient creates a new auth service client
func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if config.HMACSecret == "" {
		return nil, fmt.Errorf("HMAC secret is required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	hmacClient := hmac.NewClient(hmac.Config{
		BaseURL:    config.BaseURL,
		HMACSecret: config.HMACSecret,
		Timeout:    timeout,
	})

	return &Client{client: hmacClient}, nil
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	EmailVerified bool   `json:"emailVerified"`
}

// CreateUserResponse represents the response from creating a user
type CreateUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Data    struct {
		UserID string `json:"userId"`
	} `json:"data"`
}

// CreateUser creates a new user in auth-service
func (c *Client) CreateUser(req CreateUserRequest) (*CreateUserResponse, error) {
	resp, err := c.client.DoRequest("POST", "/api/v1/users", req)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result CreateUserResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// VerifyCredentialsRequest represents a request to verify credentials
type VerifyCredentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// VerifyCredentialsResponse represents the response from verifying credentials
type VerifyCredentialsResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Data    struct {
		OK      bool   `json:"ok"`
		UserID  string `json:"userId"`
		Blocked bool   `json:"blocked"`
	} `json:"data"`
}

// VerifyCredentials verifies user credentials
func (c *Client) VerifyCredentials(req VerifyCredentialsRequest) (*VerifyCredentialsResponse, error) {
	resp, err := c.client.DoRequest("POST", "/api/v1/auth/verify", req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result VerifyCredentialsResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// CreateSessionRequest represents a request to create a session
type CreateSessionRequest struct {
	UserID    string `json:"userId"`
	IP        string `json:"ip"`
	UserAgent string `json:"userAgent"`
}

// CreateSessionResponse represents the response from creating a session
type CreateSessionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Data    struct {
		SessionID string `json:"sessionId"`
		Secret    string `json:"secret"`
		ExpiresAt string `json:"expiresAt"`
	} `json:"data"`
}

// CreateSession creates a new session
func (c *Client) CreateSession(req CreateSessionRequest) (*CreateSessionResponse, error) {
	resp, err := c.client.DoRequest("POST", "/api/v1/sessions", req)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result CreateSessionResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ValidateSessionRequest represents a request to validate a session
type ValidateSessionRequest struct {
	Secret string `json:"secret"`
}

// ValidateSessionResponse represents the response from validating a session
type ValidateSessionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Data    struct {
		Valid  bool   `json:"valid"`
		UserID string `json:"userId"`
	} `json:"data"`
}

// ValidateSession validates a session
func (c *Client) ValidateSession(sessionID, secret string) (*ValidateSessionResponse, error) {
	req := ValidateSessionRequest{Secret: secret}
	resp, err := c.client.DoRequest("POST", fmt.Sprintf("/api/v1/sessions/%s/validate", sessionID), req)
	if err != nil {
		return nil, fmt.Errorf("failed to validate session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result ValidateSessionResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// RevokeSession revokes a session
func (c *Client) RevokeSession(sessionID string) error {
	resp, err := c.client.DoRequest("POST", fmt.Sprintf("/api/v1/sessions/%s/revoke", sessionID), nil)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return parseErrorResponse(resp.StatusCode, body)
	}

	return nil
}

// CreateTokenRequest represents a request to create a token
type CreateTokenRequest struct {
	UserID string `json:"userId"`
	Type   string `json:"type"` // "password_reset" or "email_verify"
}

// CreateTokenResponse represents the response from creating a token
type CreateTokenResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Data    struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	} `json:"data"`
}

// CreateToken creates a token (password reset or email verification)
func (c *Client) CreateToken(req CreateTokenRequest) (*CreateTokenResponse, error) {
	resp, err := c.client.DoRequest("POST", "/api/v1/tokens", req)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result CreateTokenResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// VerifyEmailRequest represents a request to verify email
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmailResponse represents the response from verifying email
type VerifyEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// VerifyEmail verifies an email using a token
func (c *Client) VerifyEmail(token string) (*VerifyEmailResponse, error) {
	req := VerifyEmailRequest{Token: token}
	resp, err := c.client.DoRequest("POST", "/api/v1/auth/verify-email", req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result VerifyEmailResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ResetPasswordRequest represents a request to reset password
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

// ResetPasswordResponse represents the response from resetting password
type ResetPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// ResetPassword resets a user's password
func (c *Client) ResetPassword(req ResetPasswordRequest) (*ResetPasswordResponse, error) {
	resp, err := c.client.DoRequest("POST", "/api/v1/auth/reset-password", req)
	if err != nil {
		return nil, fmt.Errorf("failed to reset password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result ResetPasswordResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetUserResponse represents the response from getting a user
type GetUserResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Status    int    `json:"status"`
	Timestamp string `json:"timestamp"`
	Data      struct {
		ID                string  `json:"id"`
		Email             string  `json:"email"`
		EmailVerified     bool    `json:"emailVerified"`
		Blocked           bool    `json:"blocked"`
		LastLoginAt       *string `json:"lastLoginAt,omitempty"`
		PasswordChangedAt *string `json:"passwordChangedAt,omitempty"`
		CreatedAt         string  `json:"createdAt"`
	} `json:"data"`
}

// GetUser gets a user by ID
func (c *Client) GetUser(userID string) (*GetUserResponse, error) {
	resp, err := c.client.DoRequest("GET", fmt.Sprintf("/api/v1/users/%s", userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result GetUserResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// DeleteUser soft-deletes a user by ID
func (c *Client) DeleteUser(userID string) error {
	resp, err := c.client.DoRequest("DELETE", fmt.Sprintf("/api/v1/users/%s", userID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return parseErrorResponse(resp.StatusCode, body)
	}

	return nil
}

// ListUsersRequest represents query parameters for listing users
type ListUsersRequest struct {
	Email         string // Filter by email (exact match using email_eq)
	EmailVerified *bool  // Filter by email_verified status
	Blocked       *bool  // Filter by blocked status
	Page          int    // Page number (default: 1)
	PerPage       int    // Items per page (default: 20, max: 100)
}

// ListUsersResponse represents the paginated response from listing users
type ListUsersResponse struct {
	Success    bool                  `json:"success"`
	Message    string                `json:"message"`
	Status     int                   `json:"status"`
	Timestamp  string                `json:"timestamp"`
	Data       []GetUserResponseData `json:"data"`
	Pagination *Pagination           `json:"pagination,omitempty"`
}

// Pagination contains pagination metadata
type Pagination struct {
	Page         int   `json:"page"`
	PerPage      int   `json:"perPage"`
	Total        int64 `json:"total"`
	TotalPages   int   `json:"totalPages"`
	HasNext      bool  `json:"hasNext"`
	HasPrevious  bool  `json:"hasPrevious"`
	NextPage     *int  `json:"nextPage,omitempty"`
	PreviousPage *int  `json:"previousPage,omitempty"`
}

// GetUserResponseData represents a single user in the list
type GetUserResponseData struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"emailVerified"`
	Blocked           bool   `json:"blocked"`
	LastLoginAt       string `json:"lastLoginAt,omitempty"`
	PasswordChangedAt string `json:"passwordChangedAt,omitempty"`
	CreatedAt         string `json:"createdAt"`
}

// ListUsers lists users with optional filters
func (c *Client) ListUsers(req ListUsersRequest) (*ListUsersResponse, error) {
	// Build query string
	queryParams := make([]string, 0)

	if req.Email != "" {
		queryParams = append(queryParams, fmt.Sprintf("email_eq=%s", url.QueryEscape(req.Email)))
	}
	if req.EmailVerified != nil {
		queryParams = append(queryParams, fmt.Sprintf("email_verified_eq=%t", *req.EmailVerified))
	}
	if req.Blocked != nil {
		queryParams = append(queryParams, fmt.Sprintf("blocked_eq=%t", *req.Blocked))
	}
	if req.Page > 0 {
		queryParams = append(queryParams, fmt.Sprintf("page=%d", req.Page))
	}
	if req.PerPage > 0 {
		queryParams = append(queryParams, fmt.Sprintf("per_page=%d", req.PerPage))
	}

	path := "/api/v1/users"
	if len(queryParams) > 0 {
		path += "?" + strings.Join(queryParams, "&")
	}

	resp, err := c.client.DoRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result ListUsersResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ListSessionsRequest represents query parameters for listing sessions
type ListSessionsRequest struct {
	UserID    string // Filter by user_id (UUID)
	Status    string // Filter by status: "active", "revoked", "expired"
	IP        string // Filter by IP (supports operators like ip_like)
	UserAgent string // Filter by user_agent (supports operators like user_agent_like)
	Page      int    // Page number (default: 1)
	PerPage   int    // Items per page (default: 20, max: 100)
}

// ListSessionsResponse represents the paginated response from listing sessions
type ListSessionsResponse struct {
	Success    bool              `json:"success"`
	Message    string            `json:"message"`
	Status     int               `json:"status"`
	Timestamp  string            `json:"timestamp"`
	Data       []SessionListItem `json:"data"`
	Pagination *Pagination       `json:"pagination,omitempty"`
}

// SessionListItem represents a single session in the list
type SessionListItem struct {
	ID        string  `json:"id"`
	UserID    string  `json:"userId"`
	ExpiresAt string  `json:"expiresAt"`
	RevokedAt *string `json:"revokedAt,omitempty"`
	IP        string  `json:"ip"`
	UserAgent string  `json:"userAgent"`
	CreatedAt string  `json:"createdAt"`
}

// ListSessions lists sessions with optional filters
func (c *Client) ListSessions(req ListSessionsRequest) (*ListSessionsResponse, error) {
	// Build query string
	queryParams := make([]string, 0)

	if req.UserID != "" {
		queryParams = append(queryParams, fmt.Sprintf("user_id=%s", url.QueryEscape(req.UserID)))
	}
	if req.Status != "" {
		queryParams = append(queryParams, fmt.Sprintf("status=%s", url.QueryEscape(req.Status)))
	}
	if req.IP != "" {
		queryParams = append(queryParams, fmt.Sprintf("ip_like=%s", url.QueryEscape(req.IP)))
	}
	if req.UserAgent != "" {
		queryParams = append(queryParams, fmt.Sprintf("user_agent_like=%s", url.QueryEscape(req.UserAgent)))
	}
	if req.Page > 0 {
		queryParams = append(queryParams, fmt.Sprintf("page=%d", req.Page))
	}
	if req.PerPage > 0 {
		queryParams = append(queryParams, fmt.Sprintf("per_page=%d", req.PerPage))
	}

	path := "/api/v1/sessions"
	if len(queryParams) > 0 {
		path += "?" + strings.Join(queryParams, "&")
	}

	resp, err := c.client.DoRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result ListSessionsResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetSessionResponse represents the response from getting a session
type GetSessionResponse struct {
	Success   bool            `json:"success"`
	Message   string          `json:"message"`
	Status    int             `json:"status"`
	Timestamp string          `json:"timestamp"`
	Data      SessionListItem `json:"data"`
}

// GetSession gets a session by ID
func (c *Client) GetSession(sessionID string) (*GetSessionResponse, error) {
	resp, err := c.client.DoRequest("GET", fmt.Sprintf("/api/v1/sessions/%s", sessionID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result GetSessionResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ListTokensRequest represents query parameters for listing tokens
type ListTokensRequest struct {
	UserID  string // Filter by user_id (UUID)
	Type    string // Filter by type: "password_reset" or "email_verify"
	Status  string // Filter by status: "active", "used", "expired"
	Page    int    // Page number (default: 1)
	PerPage int    // Items per page (default: 20, max: 100)
}

// ListTokensResponse represents the paginated response from listing tokens
type ListTokensResponse struct {
	Success    bool            `json:"success"`
	Message    string          `json:"message"`
	Status     int             `json:"status"`
	Timestamp  string          `json:"timestamp"`
	Data       []TokenListItem `json:"data"`
	Pagination *Pagination     `json:"pagination,omitempty"`
}

// TokenListItem represents a single token in the list
type TokenListItem struct {
	ID        string  `json:"id"`
	UserID    string  `json:"userId"`
	Type      string  `json:"type"`
	ExpiresAt string  `json:"expiresAt"`
	UsedAt    *string `json:"usedAt,omitempty"`
	CreatedAt string  `json:"createdAt"`
}

// ListTokens lists tokens with optional filters
func (c *Client) ListTokens(req ListTokensRequest) (*ListTokensResponse, error) {
	// Build query string
	queryParams := make([]string, 0)

	if req.UserID != "" {
		queryParams = append(queryParams, fmt.Sprintf("user_id=%s", url.QueryEscape(req.UserID)))
	}
	if req.Type != "" {
		queryParams = append(queryParams, fmt.Sprintf("type_eq=%s", url.QueryEscape(req.Type)))
	}
	if req.Status != "" {
		queryParams = append(queryParams, fmt.Sprintf("status=%s", url.QueryEscape(req.Status)))
	}
	if req.Page > 0 {
		queryParams = append(queryParams, fmt.Sprintf("page=%d", req.Page))
	}
	if req.PerPage > 0 {
		queryParams = append(queryParams, fmt.Sprintf("per_page=%d", req.PerPage))
	}

	path := "/api/v1/tokens"
	if len(queryParams) > 0 {
		path += "?" + strings.Join(queryParams, "&")
	}

	resp, err := c.client.DoRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result ListTokensResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetTokenResponse represents the response from getting a token
type GetTokenResponse struct {
	Success   bool          `json:"success"`
	Message   string        `json:"message"`
	Status    int           `json:"status"`
	Timestamp string        `json:"timestamp"`
	Data      TokenListItem `json:"data"`
}

// GetToken gets a token by ID
func (c *Client) GetToken(tokenID string) (*GetTokenResponse, error) {
	resp, err := c.client.DoRequest("GET", fmt.Sprintf("/api/v1/tokens/%s", tokenID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, parseErrorResponse(resp.StatusCode, body)
	}

	var result GetTokenResponse
	if err := hmac.ParseJSONResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}
