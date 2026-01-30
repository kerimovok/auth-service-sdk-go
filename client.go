package authsdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kerimovok/go-pkg-utils/hmac"
)

const (
	apiPathPrefix   = "/api/v1"
	defaultTimeout  = 10 * time.Second
	tokenTypeReset  = "password_reset"
	tokenTypeVerify = "email_verify"
	sessionActive   = "active"
	sessionRevoked  = "revoked"
	sessionExpired  = "expired"
)

// TokenType constants for CreateTokenRequest
const (
	TokenTypePasswordReset = tokenTypeReset
	TokenTypeEmailVerify   = tokenTypeVerify
)

// SessionStatus constants for ListSessionsRequest
const (
	SessionStatusActive  = sessionActive
	SessionStatusRevoked = sessionRevoked
	SessionStatusExpired = sessionExpired
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

// IsAPIError checks if an error is an APIError and returns it (use errors.As for idiomatic checks)
func IsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if err != nil && errors.As(err, &apiErr) {
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

// statusIn returns true if code is in the slice
func statusIn(code int, codes []int) bool {
	for _, c := range codes {
		if code == c {
			return true
		}
	}
	return false
}

// do performs a request, checks status, and optionally decodes JSON into result.
// successStatuses lists HTTP status codes treated as success (e.g. 200, 201).
// If result is non-nil it must be a pointer; the response body is decoded into it.
func (c *Client) do(method, path string, body interface{}, successStatuses []int, result interface{}, wrapErr string) error {
	resp, err := c.client.DoRequest(method, path, body)
	if err != nil {
		return fmt.Errorf("%s: %w", wrapErr, err)
	}
	defer resp.Body.Close()

	if !statusIn(resp.StatusCode, successStatuses) {
		respBody, _ := io.ReadAll(resp.Body)
		return parseErrorResponse(resp.StatusCode, respBody)
	}

	if result != nil {
		if err := hmac.ParseJSONResponse(resp, result); err != nil {
			return fmt.Errorf("%s: %w", wrapErr, err)
		}
	}
	return nil
}

// pathSeg escapes a path segment (e.g. userID, sessionID) for use in URLs
func pathSeg(s string) string { return url.PathEscape(s) }

// NewClient creates a new auth service client
func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if config.HMACSecret == "" {
		return nil, fmt.Errorf("HMAC secret is required")
	}

	baseURL := strings.TrimRight(config.BaseURL, "/")
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	hmacClient := hmac.NewClient(hmac.Config{
		BaseURL:    baseURL,
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
	var result CreateUserResponse
	err := c.do("POST", apiPathPrefix+"/users", req, []int{http.StatusOK, http.StatusCreated}, &result, "failed to create user")
	if err != nil {
		return nil, err
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
	var result VerifyCredentialsResponse
	err := c.do("POST", apiPathPrefix+"/auth/verify", req, []int{http.StatusOK}, &result, "failed to verify credentials")
	if err != nil {
		return nil, err
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
	var result CreateSessionResponse
	err := c.do("POST", apiPathPrefix+"/sessions", req, []int{http.StatusOK, http.StatusCreated}, &result, "failed to create session")
	if err != nil {
		return nil, err
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
	var result ValidateSessionResponse
	err := c.do("POST", apiPathPrefix+"/sessions/"+pathSeg(sessionID)+"/validate", req, []int{http.StatusOK}, &result, "failed to validate session")
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeSession revokes a session
func (c *Client) RevokeSession(sessionID string) error {
	return c.do("POST", apiPathPrefix+"/sessions/"+pathSeg(sessionID)+"/revoke", nil, []int{http.StatusOK}, nil, "failed to revoke session")
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
	var result CreateTokenResponse
	err := c.do("POST", apiPathPrefix+"/tokens", req, []int{http.StatusOK, http.StatusCreated}, &result, "failed to create token")
	if err != nil {
		return nil, err
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
	var result VerifyEmailResponse
	err := c.do("POST", apiPathPrefix+"/auth/verify-email", req, []int{http.StatusOK}, &result, "failed to verify email")
	if err != nil {
		return nil, err
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
	var result ResetPasswordResponse
	err := c.do("POST", apiPathPrefix+"/auth/reset-password", req, []int{http.StatusOK}, &result, "failed to reset password")
	if err != nil {
		return nil, err
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
	var result GetUserResponse
	err := c.do("GET", apiPathPrefix+"/users/"+pathSeg(userID), nil, []int{http.StatusOK}, &result, "failed to get user")
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteUser soft-deletes a user by ID
func (c *Client) DeleteUser(userID string) error {
	return c.do("DELETE", apiPathPrefix+"/users/"+pathSeg(userID), nil, []int{http.StatusOK, http.StatusNoContent}, nil, "failed to delete user")
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
	ID                string  `json:"id"`
	Email             string  `json:"email"`
	EmailVerified     bool    `json:"emailVerified"`
	Blocked           bool    `json:"blocked"`
	LastLoginAt       *string `json:"lastLoginAt,omitempty"`
	PasswordChangedAt *string `json:"passwordChangedAt,omitempty"`
	CreatedAt         string  `json:"createdAt"`
}

// ListUsers lists users by forwarding the raw query string to auth-service.
// Query can include page, per_page, sort_by, sort_order, and go-pkg-utils filter params (e.g. email_like=, created_at_gte=).
func (c *Client) ListUsers(queryString string) (*ListUsersResponse, error) {
	path := apiPathPrefix + "/users"
	if queryString != "" {
		path += "?" + queryString
	}
	var result ListUsersResponse
	err := c.do("GET", path, nil, []int{http.StatusOK}, &result, "failed to list users")
	if err != nil {
		return nil, err
	}
	return &result, nil
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

// ListSessions lists sessions by forwarding the raw query string to auth-service.
func (c *Client) ListSessions(queryString string) (*ListSessionsResponse, error) {
	path := apiPathPrefix + "/sessions"
	if queryString != "" {
		path += "?" + queryString
	}
	var result ListSessionsResponse
	err := c.do("GET", path, nil, []int{http.StatusOK}, &result, "failed to list sessions")
	if err != nil {
		return nil, err
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
	var result GetSessionResponse
	err := c.do("GET", apiPathPrefix+"/sessions/"+pathSeg(sessionID), nil, []int{http.StatusOK}, &result, "failed to get session")
	if err != nil {
		return nil, err
	}
	return &result, nil
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

// ListTokens lists tokens by forwarding the raw query string to auth-service.
func (c *Client) ListTokens(queryString string) (*ListTokensResponse, error) {
	path := apiPathPrefix + "/tokens"
	if queryString != "" {
		path += "?" + queryString
	}
	var result ListTokensResponse
	err := c.do("GET", path, nil, []int{http.StatusOK}, &result, "failed to list tokens")
	if err != nil {
		return nil, err
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
	var result GetTokenResponse
	err := c.do("GET", apiPathPrefix+"/tokens/"+pathSeg(tokenID), nil, []int{http.StatusOK}, &result, "failed to get token")
	if err != nil {
		return nil, err
	}
	return &result, nil
}
