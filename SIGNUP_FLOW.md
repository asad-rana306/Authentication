# Signup API Flow

This document explains how signup works in the current codebase.

## Scope

- `POST /public/signup`
- `POST /public/signup/verify`
- `POST /public/signup/resend-otp`

Related implementation:
- `src/main/java/com/FYP/IERS/Controller/PublicController.java`
- `src/main/java/com/FYP/IERS/Service/AuthenticationService/AuthenticationService.java`
- `src/main/java/com/FYP/IERS/Entity/User.java`

## 1) Register user

Endpoint: `POST /public/signup`

Request body:

```json
{
  "userName": "john123",
  "password": "john@12345",
  "email": "john@example.com",
  "phoneNumber": "+923001234567"
}
```

Validation in controller:
- `userName` is required
- `password` must be at least 6 characters
- `email` must contain `@`

Processing:
1. Create `User` entity.
2. Encode password with BCrypt.
3. Set secure defaults:
   - `enabled = false`
   - `failedLoginAttempts = 0`
   - `accountLocked = false`
4. Save user through `UserServices`.
5. Send signup OTP using exact record id: `sendSignupOtp(savedUser.getId())`.
6. In service, OTP fields are set and stored:
   - `signupOtpCode`
   - `signupExpiresAt` (5 minutes)
   - `signupAttempts = 0`
   - `signupSentAt`

Response on success: `201 Created`

```json
{
  "success": true,
  "message": "User registered successfully. Please check your email for the verification OTP.",
  "userId": 1,
  "userName": "john123",
  "timestamp": 1710000000000
}
```

## 2) Verify signup OTP

Endpoint: `POST /public/signup/verify`

Request body:

```json
{
  "userName": "john123",
  "otp": "123456"
}
```

Validation in controller:
- `userName` is required
- `otp` is required

Processing in service:
1. Load user by `userName`.
2. Reject if user not found.
3. Reject if already verified (`enabled = true`).
4. Reject if no pending OTP challenge.
5. Reject if OTP expired.
6. Reject if max attempts reached (`5`).
7. If OTP is wrong:
   - increment `signupAttempts`
   - return remaining attempts in error
8. If OTP is correct:
   - set `enabled = true`
   - clear signup OTP challenge fields
   - persist user

Response on success: `200 OK`

```json
{
  "success": true,
  "message": "Email verified successfully! You can now login.",
  "userId": 1,
  "userName": "john123",
  "timestamp": 1710000000000
}
```

## 3) Resend signup OTP

Endpoint: `POST /public/signup/resend-otp`

Request body:

```json
{
  "userName": "john123"
}
```

Validation in controller:
- `userName` is required

Processing in service:
1. Load user by `userName`.
2. Reject if user not found.
3. Reject if already verified.
4. Enforce resend cooldown (`30 seconds`).
5. Issue new OTP and reset OTP attempt counter.
6. Save updated OTP challenge state.

Response on success: `200 OK`

```json
{
  "success": true,
  "message": "A new verification code has been sent to your email.",
  "emailVerificationRequired": true,
  "otpExpiresInSeconds": 300,
  "userId": 1,
  "userName": "john123",
  "timestamp": 1710000000000
}
```

## Security rules

- New user stays disabled until OTP verification succeeds.
- OTP expiry: 5 minutes.
- OTP max verification attempts: 5.
- OTP resend cooldown: 30 seconds.
- Passwords are stored hashed (BCrypt).

## Terminal trace logs

Signup flow logs use these tags:
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

Failure traces:
- `[SIGNUP][VERIFY_FAIL_USER_NOT_FOUND]`
- `[SIGNUP][VERIFY_FAIL_NO_PENDING_CHALLENGE]`
- `[SIGNUP][VERIFY_FAIL_EXPIRED]`
- `[SIGNUP][VERIFY_FAIL_MAX_ATTEMPTS]`
- `[SIGNUP][VERIFY_FAIL_INVALID_OTP]`
- `[SIGNUP][RESEND_FAIL_USER_NOT_FOUND]`
- `[SIGNUP][RESEND_FAIL_COOLDOWN]`

