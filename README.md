🔐 Diana Global — Auth & Account API (Interview Summary)








Base URL (prod):
🔗 https://dianagloballoginregister-52599bd07634.herokuapp.com
OpenAPI: 📘 /api-docs (OAS 3.1)

🚀 What’s New (2025-10-16)

✉️ Email templates refactor (confirmation, email-change ×3, password reset): table layout (640px), inline styles, fixed logo (HTTPS), accessible CTA, footer fix (⚡ alignment), preheader for confirmation.

🔀 Email change flow split into 3 services: confirm-new, changed, alert-old.

🔐 Security polish: enforce HTTPS logo URL, Gmail clipping mitigations.

🧭 Auth Model

🔑 Access token: JSON response.

🍪 Refresh token: HttpOnly cookie refresh_token (rotated via /api/auth/refresh-token).

🛡️ CSRF: cookie csrf_token + header X-CSRF-Token.

🧾 Sessions: server-side refresh tokens + rotation + revoke on logout.

🧩 Key Endpoints (by area)
/api/auth

POST /register — create user (LOCAL), sends confirmation.

POST /login — password login → access + cookies (refresh, csrf).

POST /oauth/google — Google ID token login/registration.

POST /logout — revoke refresh + clear cookies.

POST /refresh-token — rotate refresh, new access token.

POST /password/set — first-time set (auth).

POST /password/change — change password (auth).

POST /email/change-request — start email change (sends to new email).

GET|POST /email/change-confirm?token=… — confirm email change.

POST /confirm/resend — resend account confirmation (cooldown aware).

GET|POST /confirm-account?token=… — confirm account.

GET /profile — current user profile (auth).

GET /find-user?email=… — existence check.

GET /confirmed?email=… — confirmed | not_confirmed.

🔁 Password Reset

POST /api/auth/forgot-password — request reset link.

POST /api/auth/reset-password — consume token + set password.

📝 Privacy

POST /api/privacy/consent — store/update consent.

👤 User

GET /api/user/profile — profile (alt route, auth).

📦 Core Schemas (per OpenAPI)

RegisterRequest { name?, email, password }

LoginRequest { email, password }

OAuthGoogleRequest { idToken }

NewPasswordDTO { newPassword } (≥ 8, upper/lower/digit)

ChangePasswordRequest { currentPassword, newPassword }

ForgotPasswordRequest { email }

ChangeEmailRequest { newEmail }

LoginResponse / AuthResponse { accessToken }

JwtResponse { token }

MessageResponse { message }

⚠️ Errors (typical)

400 validation / expired token

401 auth failure / missing session

403 CSRF mismatch / provider rules

409 conflicts (e.g., unconfirmed login, duplicate email)

5xx internal (with logged error id)

🎨 Branding (used by emails)

MailBranding.brandName()

MailBranding.safeLogoUrl() → absolute HTTPS image URL (fixed width/height in templates)

MailBranding.frontendUrl() (for /login, /support CTAs)

✉️ Email Template Guarantees

Table layout (640px), inline CSS, fixed logo sizing, accessible CTA

Unified header/footer (gradient: linear-gradient(135deg,#0a2239,#0e4b68))

Footer ⚡ baseline fixed across Gmail/Outlook/iOS

Gmail clipping mitigations (lean markup + zero-width char)

📫 Contact

✉️ Email: andescoresoftware@gmail.com

🧰 Issues/Requests: (open an issue in the project repository)