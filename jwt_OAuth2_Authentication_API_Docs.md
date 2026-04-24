# Authentication API Documentation (Spring Security + JWT + OAuth2)

This document describes the production authentication behavior currently implemented in the project, including signup verification, login security controls, OAuth2 login, password setup, and error handling.

## API Overview

### Public endpoints

- `POST /public/signup`
- `POST /public/signup/verify`
- `POST /public/signup/resend-otp`
- `POST /public/login`
- `POST /public/forgot-password`
- `POST /public/forgot-password/reset`
- `GET /public/health`
- `GET /oauth2/authorization/google`

### Authenticated endpoint

- `POST /auth/set-password`

Required header:

```http
Authorization: Bearer <jwt-token>
```

## Common Response Shape

Most responses use `AuthenticationResponse` and include fields such as:

- `success` (boolean)
- `message` (string)
- `timestamp` (epoch millis)
- `token` (login only)
- `userId`, `userName` (when relevant)
- `remainingAttempts` (for credential/OTP failures)
- `emailVerificationRequired`, `otpExpiresInSeconds` (OTP resend flow)

## Signup Flow

### 1) Register user

Endpoint: `POST /public/signup`

Request example:

```json
{
  "userName": "user",
  "password": "StrongPass@123",
  "email": "fafd",
  "phoneNumber": ""
}
```

Validation rules:

- `userName` is required
- `password` must be at least 6 characters
- `email` must contain `@`

Server behavior:

1. Creates user and hashes password with BCrypt.
2. Normalizes email to lowercase.
3. Stores user with `enabled=false`.
4. Sets default role `USER`.
5. Sends signup OTP to the registered email.

Success response (`201 Created`):

```json
{
  "success": true,
  "message": "User registered successfully. Please check your email for the verification OTP.",
  "userId": 1,
  "userName": "user123",
  "timestamp": 1710000000000
}
```

### 2) Verify signup OTP

Endpoint: `POST /public/signup/verify`

Request example:

```json
{
  "email": "fafdasd.com",
  "otp": "123456"
}
```

Server behavior:

1. Loads user by email.
2. Rejects if user is already enabled.
3. Rejects if OTP challenge is missing, expired, or attempts exceeded.
4. Increments `signupAttempts` on invalid OTP.
5. On success: sets `enabled=true` and clears OTP challenge fields.

Success response (`200 OK`):

```json
{
  "success": true,
  "message": "Email verified successfully! You can now login.",
  "userId": 1,
  "userName": "user123",
  "timestamp": 1710000000000
}
```

### 3) Resend signup OTP

Endpoint: `POST /public/signup/resend-otp`

Request example:

```json
{
  "email": "fasdf.com"
}
```

Server behavior:

1. Loads user by email.
2. Rejects if user already verified.
3. Enforces resend cooldown.
4. Issues new OTP, resets attempts, updates expiry.

Success response (`200 OK`):

```json
{
  "success": true,
  "message": "A new verification code has been sent to your email.",
  "emailVerificationRequired": true,
  "otpExpiresInSeconds": 300,
  "userId": 1,
  "userName": "user123",
  "timestamp": 1710000000000
}
```

## Login Flow

### 1) Username/password login

Endpoint: `POST /public/login`

Request example:

```json
{
  "userName": "user123",
  "password": "StrongPass123"
}
```

Service behavior (`AuthenticationService.authenticate`):

1. Loads user by `userName`.
2. Rejects unverified users (`enabled=false`).
3. Rejects users without local password.
4. Applies account-lock checks.
5. Authenticates via Spring `AuthenticationManager`.
6. On success: resets failed attempts, updates last login, issues JWT.
7. On invalid credentials: increments failed attempts and locks at threshold.

Success response (`200 OK`):

```json
{
  "success": true,
  "message": "Login successful",
  "token": "<jwt-token>",
  "userId": 1,
  "userName": "user123",
  "timestamp": 1710000000000
}
```

### 2) Google OAuth2 login

Endpoint: `GET /oauth2/authorization/google`

Behavior:

- Existing user by email/provider subject is reused.
- New OAuth2 user is created with `enabled=true`.
- Signup OTP is skipped for Google-authenticated users.
- JWT is returned in success handler response.

Success response (`200 OK`):

```json
{
  "success": true,
  "message": "Google login successful",
  "token": "<jwt-token>",
  "userId": 2,
  "userName": "user123",
  "timestamp": 1710000000000
}
```

### 3) Set local password (for authenticated user)

Endpoint: `POST /auth/set-password`

Request example:

```json
{
  "newPassword": "StrongPass123"
}
```

Success response (`200 OK`):

```json
{
  "success": true,
  "message": "Password set successfully. You can now login with username and password.",
  "userId": 2,
  "userName": "user123",
  "timestamp": 1710000000000
}
```

## Forgot Password Flow

### 1) Request reset OTP

Endpoint: `POST /public/forgot-password`

Request example:

```json
{
  "email": "user123example.com"
}
```

Response (`200 OK`, generic by design):

```json
{
  "success": true,
  "message": "If an account exists for that email, a reset code has been sent.",
  "timestamp": 1710000000000
}
```

### 2) Reset password with OTP

Endpoint: `POST /public/forgot-password/reset`

Request example:

```json
{
  "email": "user123@example.com",
  "otp": "123456",
  "newPassword": "NewStrongPass@123"
}
```

Response (`200 OK`):

```json
{
  "success": true,
  "message": "Password reset successful. Please login with your new password.",
  "timestamp": 1710000000000
}
```

## Security Rules and Limits

- Login max failed attempts: `3`
- Account lock duration: `15 minutes`
- OTP expiry: `5 minutes`
- OTP max verify attempts: `5`
- OTP resend cooldown: `30 seconds`
- Signup user remains disabled until OTP verification completes
- JWT-protected routes require valid bearer token

## Error Handling

### Exception mapping

Global exception handling (`GlobalExceptionHandler`) maps custom exceptions as follows:

- `AccountLockedException` -> `423 Locked`
- `InvalidCredentialsException` -> `401 Unauthorized`
- `UserDisabledException` -> `403 Forbidden`
- Any unhandled exception -> `500 Internal Server Error`

Typical error response shape:

```json
{
  "success": false,
  "message": "<error message>",
  "remainingAttempts": 2,
  "timestamp": 1710000000000
}
```

`remainingAttempts` appears when available (mainly credential/OTP attempt errors).

### Endpoint-level validation errors (`400 Bad Request`)

These are returned directly from controllers when required fields are missing or invalid:

- Signup: missing `userName`, weak `password`, invalid `email`
- Signup verify: missing `email` or `otp`
- Signup resend OTP: missing `email`
- Login: missing `userName` or `password`
- Forgot password: missing `email`
- Reset password: missing `email`, missing `otp`, weak `newPassword`

Example:

```json
{
  "success": false,
  "message": "Email is required",
  "timestamp": 1710000000000
}
```

### Authentication and authorization errors

- Missing/invalid JWT on protected routes -> `401 Unauthorized`
  - Message: `Unauthorized: missing or invalid token`
- Valid JWT but insufficient authority -> `403 Forbidden`
  - Message: `Forbidden: insufficient permissions`

### OAuth2-specific errors

OAuth2 failure handler returns:

- `401 Unauthorized`
- Message format: `Google authentication failed: <provider message>`

Example:

```json
{
  "success": false,
  "message": "Google authentication failed: <reason>",
  "timestamp": 1710000000000
}
```

## Operational Trace Tags

Signup and verification logs include tags used for tracing:

- `[SIGNUP][REGISTER_SUCCESS]`
- `[SIGNUP][OTP_SEND_INIT]`
- `[SIGNUP][OTP_ISSUED]`
- `[SIGNUP][OTP_SEND_DONE]`
- `[SIGNUP][VERIFY_REQUEST]`
- `[SIGNUP][VERIFY_INIT]`
- `[SIGNUP][VERIFY_SUCCESS]`
- `[SIGNUP][RESEND_REQUEST]`
- `[SIGNUP][RESEND_INIT]`
- `[SIGNUP][RESEND_SUCCESS]`

Google authentication logs include:

- `[GOOGLE][AUTH_INIT]`
- `[GOOGLE][USER_CREATED]`
- `[GOOGLE][AUTH_SUCCESS]`
