# Auth Service SDK

A Go SDK for interacting with the auth-service microservice. This SDK provides a
type-safe client for all auth-service operations including user management,
session handling, and token operations.

## Installation

```bash
go get github.com/kerimovok/auth-service-sdk-go
```

## Features

- **Type-Safe**: Full type definitions for all requests and responses
- **Error Handling**: Comprehensive error handling with detailed error messages
- **User Management**: Create, get, list, update, and delete users; change
  password and email; block and unblock users
- **Session Management**: Create, validate, revoke (DELETE), get, and list
  sessions; list/revoke user-scoped sessions; revoke all or other sessions ("log
  out everywhere" / "log out other devices")
- **Token Management**: Create, verify, get, list, and revoke tokens;
  list/revoke user-scoped tokens (list user tokens, revoke one or all for a
  user)
- **Filtering & Pagination**: Support for filtering and pagination on list
  endpoints

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
        BaseURL: "http://localhost:3001",
        Timeout: 10 * time.Second,
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
//                     user.Data.Blocked, user.Data.LastLoginAt, user.Data.LastLoginIP,
//                     user.Data.LastLoginUserAgent, user.Data.PasswordChangedAt,
//                     user.Data.CreatedAt
```

#### ListUsers

Lists users with optional filters and pagination. Pass a query string (e.g.
`page=1&per_page=20`, filter params like `email_like=example`,
`email_verified_eq=true`, `blocked_eq=false`, `created_at_gte=2024-01-01`).

```go
resp, err := client.ListUsers("page=1&per_page=20&blocked_eq=false")
// Access users: resp.Data (array of GetUserResponseData)
// Access pagination: resp.Pagination
// Each user in resp.Data contains: ID, Email, EmailVerified, Blocked,
//                                   LastLoginAt, LastLoginIP, LastLoginUserAgent,
//                                   PasswordChangedAt, CreatedAt
```

#### UpdateUser

Updates a user's email, emailVerified, and/or blocked status.

```go
resp, err := client.UpdateUser("user-uuid", authsdk.UpdateUserRequest{
    Email:         &newEmail, // optional
    EmailVerified: &true,     // optional
    Blocked:       &false,    // optional
})
// Response: same shape as GetUser
```

#### DeleteUser

Soft-deletes a user by ID.

```go
err := client.DeleteUser("user-uuid")
```

#### ChangePassword

Changes a user's password. For self-service, provide `OldPassword`; omit it for
admin reset.

```go
err := client.ChangePassword("user-uuid", authsdk.ChangePasswordRequest{
    OldPassword: &currentPassword, // optional; required for self-service
    NewPassword: "newSecurePassword456",
})
```

#### ChangeEmail

Changes a user's email. The new email will be unverified until the user
completes verification.

```go
err := client.ChangeEmail("user-uuid", authsdk.ChangeEmailRequest{
    NewEmail: "newemail@example.com",
})
```

#### BlockUser

Blocks a user (sets `blocked=true` and revokes all their sessions in
auth-service).

```go
resp, err := client.BlockUser("user-uuid")
// Response: same shape as GetUser (updated user with blocked: true)
```

#### UnblockUser

Unblocks a user (sets `blocked=false`).

```go
resp, err := client.UnblockUser("user-uuid")
// Response: same shape as GetUser (updated user with blocked: false)
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

Creates a new session for a user. Set `RememberMe` to true for longer-lived
sessions (when the auth-service is configured for it).

```go
resp, err := client.CreateSession(authsdk.CreateSessionRequest{
    UserID:     "user-uuid",
    IP:         "192.168.1.1",
    UserAgent:  "Mozilla/5.0...",
    RememberMe: false, // optional; longer session expiry when true
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

Revokes a session by ID (REST: DELETE /sessions/:id).

```go
err := client.RevokeSession("session-uuid")
```

#### RevokeUserSession

Revokes a single session for a user (DELETE /users/:userId/sessions/:sessionId).
Use when revoking a specific session in a user-scoped context.

```go
err := client.RevokeUserSession("user-uuid", "session-uuid")
```

#### RevokeAllUserSessions

Revokes all sessions for a user ("log out everywhere").

```go
err := client.RevokeAllUserSessions("user-uuid")
```

#### RevokeOtherSessions

Revokes all sessions for a user except the given session ("log out other
devices"). Use the current session ID as `exceptSessionID` so the current device
stays logged in.

```go
err := client.RevokeOtherSessions("user-uuid", "current-session-uuid")
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

Lists sessions with optional filters and pagination. Pass a query string (e.g.
`page=1&per_page=20`, `user_id_eq=uuid`, `status=active`, `ip_like=192.168`).

```go
resp, err := client.ListSessions("page=1&per_page=20&user_id_eq=user-uuid&status=active")
// Access sessions: resp.Data (array of SessionListItem)
// Access pagination: resp.Pagination
// Each session in resp.Data contains: ID, UserID, ExpiresAt, RevokedAt,
//                                       IP, UserAgent, CreatedAt
```

To list sessions for a single user, use `ListSessions("user_id_eq="+userID)` or
add other query params (e.g. `&status=active`).

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
//                     token.Data.ExpiresAt, token.Data.UsedAt, token.Data.RevokedAt,
//                     token.Data.CreatedAt
```

#### RevokeToken

Revokes a token by ID (REST: DELETE /api/v1/tokens/:id). Idempotent: returns
success if the token is already revoked.

```go
err := client.RevokeToken("token-uuid")
```

#### RevokeAllUserTokens

Revokes all tokens for a user (DELETE /api/v1/users/:userId/tokens).

```go
err := client.RevokeAllUserTokens("user-uuid")
```

#### ListUserTokens

Lists tokens for a user (GET /api/v1/users/:userId/tokens). Pass a query string
for filters and pagination (e.g. `page=1&per_page=20&status=active`,
`type_eq=password_reset`).

```go
resp, err := client.ListUserTokens("user-uuid", "page=1&per_page=20&status=active")
// Same response shape as ListTokens: resp.Data ([]TokenListItem), resp.Pagination
```

#### RevokeUserToken

Revokes a single token for a user (DELETE
/api/v1/users/:userId/tokens/:tokenId). Verifies the token belongs to that user.

```go
err := client.RevokeUserToken("user-uuid", "token-uuid")
```

#### ListTokens

Lists tokens with optional filters and pagination. Pass a query string (e.g.
`page=1&per_page=20`, `user_id_eq=uuid`, `type_eq=password_reset`,
`status=active` or `status=revoked`).

```go
resp, err := client.ListTokens("page=1&per_page=20&user_id_eq=user-uuid&type_eq=password_reset")
// Access tokens: resp.Data (array of TokenListItem)
// Access pagination: resp.Pagination
// Each token in resp.Data contains: ID, UserID, Type, ExpiresAt, UsedAt, RevokedAt, CreatedAt
```

## Configuration

The SDK uses plain HTTP and requires:

- **BaseURL**: The base URL of the auth-service (e.g., "http://localhost:3001")
- **Timeout**: Request timeout (optional, defaults to 10 seconds)

## Error Handling

All methods return errors that can be checked. The SDK provides an `APIError`
type for API-level errors:

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

Use `authsdk.IsAPIError(err)` to check if an error is an `APIError` and extract
detailed information.

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
