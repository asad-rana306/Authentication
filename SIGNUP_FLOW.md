# Signup API Flow

This file documents the current signup implementation in the project.

## Endpoints

- `POST /public/signup`
- `POST /public/signup/verify`
- `POST /public/signup/resend-otp`

## 1) Signup request

Endpoint: `POST /public/signup`

Example request:

```json
{
  "userName": "asad",
  "password": "Asad@12345",
  "email": "asad@example.com",
  "phoneNumber": "+923001234567"
}
```

Controller validation:
- `userName` is required
- `password` must be at least 6 characters
- `email` must be a valid email-like value (contains `@`)

Server flow:
1. User is created with password encoded using BCrypt.
2. Email is normalized to lowercase and saved.
3. User is stored with `enabled=false`.
4. Default role `USER` is assigned.
5. `sendSignupOtp(savedUser.getId())` sends OTP for the exact created user record.

Success response (`201`):

```json
{
  "success": true,
  "message": "User registered successfully. Please check your email for the verification OTP.",
  "userId": 1,
  "userName": "asad",
  "timestamp": 1710000000000
}
```

## 2) Verify signup OTP (email-based)

Endpoint: `POST /public/signup/verify`

Example request:

```json
{
  "email": "asad@example.com",
  "otp": "123456"
}
```

Flow:
1. User is loaded by `email`.
2. Verification fails if user not found, already enabled, no OTP state, OTP expired, or attempts exceeded.
3. Wrong OTP increments `signupAttempts`.
4. Correct OTP sets `enabled=true` and clears OTP challenge fields.

Success response (`200`):

```json
{
  "success": true,
  "message": "Email verified successfully! You can now login.",
  "userId": 1,
  "userName": "asad",
  "timestamp": 1710000000000
}
```

## 3) Resend signup OTP (email-based)

Endpoint: `POST /public/signup/resend-otp`

Example request:

```json
{
  "email": "asad@example.com"
}
```

Flow:
1. User is loaded by `email`.
2. Verification fails if user not found or already verified.
3. Cooldown is enforced for resend requests.
4. A new OTP is issued, attempts reset, and expiration updated.

Success response (`200`):

```json
{
  "success": true,
  "message": "A new verification code has been sent to your email.",
  "emailVerificationRequired": true,
  "otpExpiresInSeconds": 300,
  "userId": 1,
  "userName": "asad",
  "timestamp": 1710000000000
}
```

## Security rules

- User remains disabled until OTP verification succeeds.
- OTP expiry: 5 minutes.
- Max OTP verify attempts: 5.
- OTP resend cooldown: 30 seconds.
- Duplicate username and duplicate email are blocked during signup.
- Google OAuth2 users do not require signup OTP; their account is marked verified after Google success.

## Trace log tags

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


