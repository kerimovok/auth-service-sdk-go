# Auth Service SDK

A Go SDK for interacting with the auth-service microservice. This SDK provides a type-safe client for all auth-service operations including user management, session handling, and token operations.

## Installation

```bash
go get github.com/kerimovok/auth-service-sdk-go
```

The SDK depends on `github.com/kerimovok/go-pkg-utils` for HMAC-signed HTTP requests; it is resolved automatically via `go mod`.

## Features

- **HMAC Authentication**: All requests are automatically signed with HMAC-SHA256
- **Type-Safe**: Full type definitions for all requests and responses
- **Error Handling**: Comprehensive error handling with detailed error messages
- **User Management**: Create, get, and list users with filtering
- **Session Management**: Create, validate, revoke, get, and list user sessions
- **Token Management**: Create, verify, get, and list tokens for password reset and email verification
- **Filtering & Pagination**: Support for filtering and pagination on list endpoints

## Quick Start

```go
package main

import (
    "fmt"
    "time"
    
    authsdk "github.com/kerimovok/auth-service-sdk-go"
)

func main() {
    // Create client
    client, err := authsdk.NewClient(authsdk.Config{
        BaseURL:    "http://localhost:3001",
        HMACSecret: "your-shared-secret",
        Timeout:    10 * time.Second,
    })
    if err != nil {
        panic(err)
    }

    // Create a user
    userResp, err := client.CreateUser(authsdk.CreateUserRequest{
        Email:         "user@example.com",
        Password:      "securePassword123",
        EmailVerified: false,
    })
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("User created: %s\n", userResp.Data.UserID)
}
```

## API Reference

### User Operations

#### CreateUser

Creates a new user in the auth-service.

```go
resp, err := client.CreateUser(authsdk.CreateUserRequest{
    Email:         "user@example.com",
    Password:      "securePassword123",
    EmailVerified: false,
})
```

#### GetUser

Retrieves a user by ID.

```go
user, err := client.GetUser("user-uuid")
// Response contains: user.Data.ID, user.Data.Email, user.Data.EmailVerified,
//                     user.Data.Blocked, user.Data.LastLoginAt, user.Data.PasswordChangedAt,
//                     user.Data.CreatedAt
```

#### ListUsers

Lists users with optional filters and pagination.

```go
resp, err := client.ListUsers(authsdk.ListUsersRequest{
    Email:         "user@example.com",  // Filter by email (exact match via email_eq)
    EmailVerified: &true,                // Filter by email verification status (email_verified_eq)
    Blocked:       &false,               // Filter by blocked status (blocked_eq)
    Page:          1,                    // Page number (default: 1)
    PerPage:       20,                   // Items per page (default: 20, max: 100)
})
// Access users: resp.Data (array of GetUserResponseData)
// Access pagination: resp.Pagination
// Each user in resp.Data contains: ID, Email, EmailVerified, Blocked,
//                                   LastLoginAt, PasswordChangedAt, CreatedAt
```

#### DeleteUser

Soft-deletes a user by ID.

```go
err := client.DeleteUser("user-uuid")
```

#### VerifyCredentials

Verifies user credentials (email and password).

```go
resp, err := client.VerifyCredentials(authsdk.VerifyCredentialsRequest{
    Email:    "user@example.com",
    Password: "securePassword123",
})
// Response contains: resp.Data.OK, resp.Data.UserID, resp.Data.Blocked
```

### Session Operations

#### CreateSession

Creates a new session for a user.

```go
resp, err := client.CreateSession(authsdk.CreateSessionRequest{
    UserID:    "user-uuid",
    IP:        "192.168.1.1",
    UserAgent: "Mozilla/5.0...",
})
// Response contains: resp.Data.SessionID, resp.Data.Secret, resp.Data.ExpiresAt
```

#### ValidateSession

Validates an existing session.

```go
resp, err := client.ValidateSession("session-uuid", "session-secret")
// Response contains: resp.Data.Valid, resp.Data.UserID
```

#### RevokeSession

Revokes a session.

```go
err := client.RevokeSession("session-uuid")
```

#### GetSession

Retrieves a session by ID.

```go
session, err := client.GetSession("session-uuid")
// Response contains: session.Data.ID, session.Data.UserID, session.Data.ExpiresAt,
//                     session.Data.RevokedAt, session.Data.IP, session.Data.UserAgent,
//                     session.Data.CreatedAt
```

#### ListSessions

Lists sessions with optional filters and pagination.

```go
resp, err := client.ListSessions(authsdk.ListSessionsRequest{
    UserID:    "user-uuid",        // Filter by user ID (user_id)
    Status:    "active",            // Filter by status: "active", "revoked", "expired"
    IP:        "192.168.1",         // Filter by IP (ip_like - supports partial match)
    UserAgent: "Mozilla",           // Filter by user agent (user_agent_like - supports partial match)
    Page:      1,                   // Page number
    PerPage:   20,                  // Items per page
})
// Access sessions: resp.Data (array of SessionListItem)
// Access pagination: resp.Pagination
// Each session in resp.Data contains: ID, UserID, ExpiresAt, RevokedAt,
//                                       IP, UserAgent, CreatedAt
```

### Token Operations

#### CreateToken

Creates a token for password reset or email verification.

```go
resp, err := client.CreateToken(authsdk.CreateTokenRequest{
    UserID: "user-uuid",
    Type:   "email_verify", // or "password_reset"
})
// Response contains: resp.Data.Token, resp.Data.ExpiresAt
```

#### VerifyEmail

Verifies an email using a token.

```go
resp, err := client.VerifyEmail("verification-token")
```

#### ResetPassword

Resets a user's password using a token.

```go
resp, err := client.ResetPassword(authsdk.ResetPasswordRequest{
    Token:       "reset-token",
    NewPassword: "newSecurePassword456",
})
```

#### GetToken

Retrieves a token by ID.

```go
token, err := client.GetToken("token-uuid")
// Response contains: token.Data.ID, token.Data.UserID, token.Data.Type,
//                     token.Data.ExpiresAt, token.Data.UsedAt, token.Data.CreatedAt
```

#### ListTokens

Lists tokens with optional filters and pagination.

```go
resp, err := client.ListTokens(authsdk.ListTokensRequest{
    UserID:  "user-uuid",           // Filter by user ID (user_id)
    Type:    "password_reset",      // Filter by type: "password_reset" or "email_verify" (type_eq)
    Status:  "active",              // Filter by status: "active", "used", "expired"
    Page:    1,                     // Page number
    PerPage: 20,                    // Items per page
})
// Access tokens: resp.Data (array of TokenListItem)
// Access pagination: resp.Pagination
// Each token in resp.Data contains: ID, UserID, Type, ExpiresAt, UsedAt, CreatedAt
```

## Configuration

The SDK requires the following configuration:

- **BaseURL**: The base URL of the auth-service (e.g., "http://localhost:3001")
- **HMACSecret**: The shared secret for HMAC authentication
- **Timeout**: Request timeout (optional, defaults to 10 seconds)

## Error Handling

All methods return errors that can be checked. The SDK provides an `APIError` type for API-level errors:

```go
resp, err := client.CreateUser(req)
if err != nil {
    // Check if it's an APIError to access status code and message
    if apiErr, ok := authsdk.IsAPIError(err); ok {
        fmt.Printf("API Error (status %d): %s\n", apiErr.StatusCode, apiErr.Message)
        // apiErr.Body contains the raw response body for debugging
    } else {
        // Network or other errors
        fmt.Printf("Error: %v\n", err)
    }
    return
}
```

### APIError

The `APIError` type provides:
- `StatusCode`: HTTP status code from the API
- `Message`: Error message from the API response
- `Body`: Raw response body (useful for debugging)

Use `authsdk.IsAPIError(err)` to check if an error is an `APIError` and extract detailed information.

## Response Structure

### Standard Responses

Responses typically include:
- `success`: Boolean indicating success/failure
- `message`: Human-readable message
- `status`: HTTP status code
- `data`: Response data (varies by endpoint)

List and get-by-id responses also include `timestamp` (ISO 8601).

### Paginated Responses

List endpoints return paginated responses with:
- `data`: Array of items
- `pagination`: Pagination metadata object containing:
  - `page`: Current page number
  - `perPage`: Items per page
  - `total`: Total number of items
  - `totalPages`: Total number of pages
  - `hasNext`: Whether there's a next page
  - `hasPrevious`: Whether there's a previous page
  - `nextPage`: Next page number (if available)
  - `previousPage`: Previous page number (if available)

### JSON Format

All requests and responses use camelCase JSON field names:
- `userId` (not `user_id`)
- `emailVerified` (not `email_verified`)
- `sessionId` (not `session_id`)
- `expiresAt` (not `expires_at`)
- etc.

## License

MIT
