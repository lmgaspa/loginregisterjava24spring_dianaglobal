# 🔐 Diana Global — Auth & Account API (Interview Summary)

## 🔗 API Links

- 🌐 **Base URL (prod):** https://dianagloballoginregister-52599bd07634.herokuapp.com
- 📘 **OpenAPI (OAS 3.1):** `/api-docs`
- 🧭 **Swagger UI:** https://dianagloballoginregister-52599bd07634.herokuapp.com/swagger

## 🛠️ Tech Stack

- ☕ **Java:** 24
- 🌱 **Spring Framework / Spring Boot:** 6.x / 3.x
- 🧩 **Architecture:** Hexagonal (Ports & Adapters)
- 🗄️ **Database:** PostgreSQL
- ☁️ **Cloud:** Heroku
---

## 🚀 What’s New (2025-10-16)

- ✉️ Email templates refactor: 640px table layout, inline CSS, fixed-size HTTPS logo, accessible CTA, aligned footer, and preheader.
- 🔀 Email change flow split into 3 services: `confirm-new`, `changed`, `alert-old`.
- 🔐 Security polish: enforced HTTPS logo URL + Gmail clipping mitigations.

---

## 🧭 Auth Model

- 🔑 Access token: returned in the login JSON body
- 🍪 Refresh token: HttpOnly cookie `refresh_token` (rotated via `/api/auth/refresh-token`)
- 🛡️ CSRF: cookie `csrf_token` + header `X-CSRF-Token`
- 🧾 Sessions: server-side refresh tokens with rotation and revocation on logout

---

## 🧩 Key Endpoints (by area)

**Base:** `/api/auth`

### 🧱 Core
- `POST /register` — create user (LOCAL) and send confirmation
- `POST /login` — password login → access + cookies (refresh, csrf)
- `POST /oauth/google` — login/registration via Google ID Token
- `POST /logout` — revoke refresh and clear cookies
- `POST /refresh-token` — rotate refresh and return a new access token

### 🔑 Passwords
- `POST /password/set` — set password (first access, auth)
- `POST /password/change` — change password (auth)

### 📧 Email
- `POST /email/change-request` — start email change (sends to the new email)
- `GET|POST /email/change-confirm?token=…` — confirm the change

### ✅ Account Confirmation
- `POST /confirm/resend` — resend account confirmation (cooldown aware)
- `GET|POST /confirm-account?token=…` — confirm account

### 👤 User / Utils
- `GET /profile` — current user profile (auth)
- `GET /find-user?email=…` — check existence
- `GET /confirmed?email=…` — `confirmed` | `not_confirmed`

---

## 🔁 Password Reset

- `POST /api/auth/forgot-password` — request a reset link
- `POST /api/auth/reset-password` — consume token and set a new password

---

## 📝 Privacy

- `POST /api/privacy/consent` — store/update consent

---

## 📦 Core Schemas (OpenAPI)

- `RegisterRequest { name?, email, password }`
- `LoginRequest { email, password }`
- `OAuthGoogleRequest { idToken }`
- `NewPasswordDTO { newPassword }` (≥ 8, upper/lower/digit)
- `ChangePasswordRequest { currentPassword, newPassword }`
- `ForgotPasswordRequest { email }`
- `ChangeEmailRequest { newEmail }`
- `LoginResponse | AuthResponse { accessToken }`
- `JwtResponse { token }`
- `MessageResponse { message }`

---

## ⚠️ Errors (typical)

- 400 — validation / expired token
- 401 — auth failure / missing session
- 403 — CSRF mismatch / provider rules
- 409 — conflicts (e.g., unconfirmed login, duplicate email)
- 5xx — internal (with logged error id)

---

## 🎨 Branding (emails)

- `MailBranding.brandName()`
- `MailBranding.safeLogoUrl()` → absolute HTTPS image URL (fixed width/height in templates)
- `MailBranding.frontendUrl()` → base for CTAs (`/login`, `/support`)

---

## ✉️ Email Template Guarantees

- 640px table layout, inline CSS, fixed logo sizing, accessible CTA
- Unified header/footer (gradient: `linear-gradient(135deg,#0a2239,#0e4b68)`)
- Gmail clipping mitigations (lean markup + zero-width character)

## 🧱 Architecture (Brief)

### Domain
Use cases and core rules (framework-agnostic).

### Adapters
Web (REST controllers), mail, persistence.

### Config
Profiles and infrastructure wiring.

### Testing
Unit for use cases; contract/integration for adapters.

## 📫 Contact

- ✉️ Email: andescoresoftware@gmail.com
- Issues/Requests: open an issue in this repository
