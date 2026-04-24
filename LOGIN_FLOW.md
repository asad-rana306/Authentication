# Login API Flow

This file documents the current login implementation.

## Endpoints

- `POST /public/login`
- `GET /oauth2/authorization/google`
- `POST /auth/set-password`

## Login request

Endpoint: `POST /public/login`

Example request:

```json
{
  "userName": "asad",
  "password": "Asad@12345"
}
```

Controller validation:
- `userName` is required
- `password` is required

## Service flow

`AuthenticationService.authenticate(userName, password)` performs:

1. Load user by `userName`.
2. If user does not exist, return invalid credentials response.
3. If user is not verified (`enabled=false`), reject login.
4. If account is locked and lock time not expired, reject login.
5. Authenticate credentials via Spring Security `AuthenticationManager`.
6. On success:
   - reset failed attempts
   - update last successful login timestamp
   - generate JWT token
7. On invalid password:
   - increment failed attempts
   - lock account after 3 failed attempts for 15 minutes

## Success response (`200`)

```json
{
  "success": true,
  "message": "Login successful",
  "token": "<jwt-token>",
  "userId": 1,
  "userName": "asad",
  "timestamp": 1710000000000
}
```

## Google OAuth2 login (no OTP required)

Start login from browser:

- `GET /oauth2/authorization/google`

After Google authentication succeeds, backend returns JSON with your JWT token.

Example success response:

```json
{
  "success": true,
  "message": "Google login successful",
  "token": "<jwt-token>",
  "userId": 2,
  "userName": "asad",
  "timestamp": 1710000000000
}
```

Behavior:
- Existing user by email is reused.
- New Google user is auto-created with `enabled=true`.
- OTP is skipped for Google-authenticated users.
- Google accounts can initially have no local password.

## Set local password for Google-authenticated user

This endpoint lets a Google-authenticated user create a local password later.

Endpoint: `POST /auth/set-password`

Headers:
- `Authorization: Bearer <jwt-token-from-google-login>`

Request body:

```json
{
  "newPassword": "Asad@12345"
}
```

Success response:

```json
{
  "success": true,
  "message": "Password set successfully. You can now login with username and password.",
  "userId": 2,
  "userName": "asad",
  "timestamp": 1710000000000
}
```

## Failure behavior

- Invalid username/password: `401`
- Unverified account: `403`
- Locked account: `423`

## Account lock policy

- Max failed login attempts: 3
- Lock duration: 15 minutes

## Notes

- Login is username-based in current code (`userName`), not email-based.
- Signup email verification must be completed before login succeeds.

