package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.AccessResponse;
import com.dianaglobal.loginregister.adapter.in.dto.OAuthGoogleRequest;
import com.dianaglobal.loginregister.adapter.in.dto.ProfileResponseDTO;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginResponse;
import com.dianaglobal.loginregister.adapter.in.dto.password.ForgotPasswordRequest;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.AccountConfirmationService;
import com.dianaglobal.loginregister.application.service.JwtService;
import com.dianaglobal.loginregister.application.service.RefreshTokenService;
import com.dianaglobal.loginregister.application.service.UserService;
import com.dianaglobal.loginregister.domain.model.User;
import com.dianaglobal.loginregister.security.CsrfTokenService;
import com.dianaglobal.loginregister.adapter.out.mail.PasswordSetEmailService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Duration;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    // ======== Constantes (evita duplicação de strings / facilita extensão) ========
    private static final String HDR_SET_COOKIE = HttpHeaders.SET_COOKIE;
    private static final String HDR_EXPOSE = "Access-Control-Expose-Headers";
    private static final String HDR_CSRF = "X-CSRF-Token";
    private static final String CT_JSON = "application/json";
    private static final String COOKIE_REFRESH = "refresh_token";
    private static final String COOKIE_CSRF = "csrf_token";
    private static final String COOKIE_PATH = "/api/auth"; // manter consistente no set e clear
    private static final String SAME_SITE_NONE = "None";
    private static final String SAME_SITE_LAX = "Lax";

    // ======== Casos de uso / serviços (pontos de extensão) ========
    private final RegisterUserUseCase registerService;
    private final AccountConfirmationService accountConfirmationService;
    private final UserService userService;
    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final CsrfTokenService csrfTokenService;

    // E-mail de notificação de criação/alteração de senha
    private final PasswordSetEmailService passwordSetEmailService;

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    @Value("${application.cookies.secure:true}")
    private boolean cookiesSecure;

    // usa a mesma duration do back (ex.: PT7D)
    @Value("${application.jwt.refresh-ttl:PT7D}")
    private Duration refreshTtl;

    public record MessageResponse(String message) {}

    @Autowired(required = false)
    private GoogleIdTokenVerifier googleTokenVerifier;

    // ===================== Helpers de cookie/headers (OCP-friendly) =====================
    private ResponseCookie buildRefreshCookie(String token, long maxAgeSeconds, String sameSite) {
        return ResponseCookie.from(COOKIE_REFRESH, token == null ? "" : token)
                .httpOnly(true)
                .secure(cookiesSecure)
                .sameSite(sameSite)
                .path(COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .build();
    }

    private ResponseCookie buildCsrfCookie(String token, long maxAgeSeconds, String sameSite) {
        return ResponseCookie.from(COOKIE_CSRF, token == null ? "" : token)
                .httpOnly(false) // legível pelo front para mandar em X-CSRF-Token
                .secure(cookiesSecure)
                .sameSite(sameSite)
                .path(COOKIE_PATH) // manter igual ao set
                .maxAge(maxAgeSeconds)
                .build();
    }

    private void setAuthCookies(HttpServletResponse response, String refresh, String csrf) {
        long maxAge = refreshTtl.getSeconds();
        ResponseCookie refreshCookie = buildRefreshCookie(refresh, maxAge, SAME_SITE_NONE);
        ResponseCookie csrfCookie    = buildCsrfCookie(csrf,    maxAge, SAME_SITE_NONE);
        response.addHeader(HDR_SET_COOKIE, refreshCookie.toString());
        response.addHeader(HDR_SET_COOKIE, csrfCookie.toString());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        ResponseCookie refreshCookie = buildRefreshCookie("", 0, SAME_SITE_LAX);
        ResponseCookie csrfCookie    = buildCsrfCookie("", 0, SAME_SITE_LAX);
        response.addHeader(HDR_SET_COOKIE, refreshCookie.toString());
        response.addHeader(HDR_SET_COOKIE, csrfCookie.toString());
    }

    private void exposeCsrfHeader(HttpServletResponse response, String csrf) {
        response.addHeader(HDR_CSRF, csrf);
        response.addHeader(HDR_EXPOSE, HDR_CSRF);
    }

    // ===================== REGISTER =====================
    @PostMapping(value = "/register", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<MessageResponse> register(@RequestBody @Valid com.dianaglobal.loginregister.adapter.in.dto.password.RegisterRequest request) {
        final String name = request.name() == null ? null : request.name().trim();
        final String email = request.email().trim().toLowerCase();
        final String password = request.password();

        try {
            registerService.register(name, email, password);

            try {
                accountConfirmationService.requestConfirmation(email, frontendBaseUrl);
            } catch (Exception mailEx) {
                log.warn("[REGISTER WARN] failed to send confirmation e-mail: {}", mailEx.getMessage());
            }

            URI location = URI.create("/api/auth/find-user?email=" + email);
            return ResponseEntity.created(location)
                    .header(HttpHeaders.LOCATION, location.toString())
                    .body(new MessageResponse("User successfully registered. Please check your e-mail to confirm your account."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        } catch (DuplicateKeyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new MessageResponse("E-mail is already registered"));
        } catch (Exception e) {
            String id = UUID.randomUUID().toString();
            log.error("[REGISTER ERROR {}] {}", id, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error. Code: " + id));
        }
    }

    // ===================== LOGIN (password) =====================
    @PostMapping(value = "/login", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest request, HttpServletResponse response) {
        var userOpt = userRepositoryPort.findByEmail(request.email().trim().toLowerCase());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid credentials"));
        }

        User user = userOpt.get();

        if ("GOOGLE".equalsIgnoreCase(user.getAuthProvider()) && !user.isPasswordSet()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Use Sign in with Google or set a password first."));
        }

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid credentials"));
        }

        if (!user.isEmailConfirmed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Please confirm your e-mail to sign in"));
        }

        String access = jwtService.generateAccessToken(user.getEmail());
        var refreshModel = refreshTokenService.create(user.getEmail()); // persiste/rotaciona no servidor
        String refresh = refreshModel.getToken();
        String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

        setAuthCookies(response, refresh, csrf);
        exposeCsrfHeader(response, csrf);

        // refresh não é mais retornado no body
        return ResponseEntity.ok(new LoginResponse(access, null));
    }

    // ===================== LOGIN (Google OAuth) =====================
    @PostMapping(value = "/oauth/google", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<?> oauthWithGoogle(@RequestBody @Valid OAuthGoogleRequest req, HttpServletResponse response) {
        if (googleTokenVerifier == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body(new MessageResponse("Google OAuth not configured on the server"));
        }

        try {
            GoogleIdToken verified = googleTokenVerifier.verify(req.idToken());
            if (verified == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("Invalid Google ID token"));
            }

            var payload = verified.getPayload();
            String email = (String) payload.get("email");
            Boolean emailVerified = (Boolean) payload.get("email_verified");
            String name = (String) payload.getOrDefault("name", "");
            String sub = payload.getSubject();

            if (email == null || Boolean.FALSE.equals(emailVerified)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("Unverified Google account"));
            }

            email = email.trim().toLowerCase();
            User user = registerService.registerOauthUser(name, email, sub);

            // ✅ Garante que o provider seja persistido como GOOGLE sem zerar flags de senha local
            String provider = user.getAuthProvider();
            if (provider == null || !"GOOGLE".equalsIgnoreCase(provider)) {
                user.setAuthProvider("GOOGLE");
            }
            if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
                user.setPasswordSet(false);
            }
            userRepositoryPort.save(user); // persistir mudanças

            String access = jwtService.generateAccessToken(user.getEmail());
            var refreshModel = refreshTokenService.create(user.getEmail());
            String refresh = refreshModel.getToken();
            String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

            setAuthCookies(response, refresh, csrf);
            exposeCsrfHeader(response, csrf);

            return ResponseEntity.ok(new LoginResponse(access, null));
        } catch (Exception e) {
            log.error("[GOOGLE OAUTH ERROR] {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error"));
        }
    }

    // ===================== SET PASSWORD =====================
    public record NewPasswordDTO(
            @jakarta.validation.constraints.Pattern(
                    regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).{8,}$",
                    message = "Password must include at least 1 uppercase letter, 1 lowercase letter, and 1 digit and be at least 8 characters"
            ) String newPassword
    ) {}

    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/password/set", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<MessageResponse> setPassword(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid NewPasswordDTO body
    ) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Not authenticated"));
        }

        var user = userRepositoryPort.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        final boolean wasPasswordSetBefore = user.isPasswordSet();

        user.setPassword(passwordEncoder.encode(body.newPassword()));
        user.setPasswordSet(true);
        userRepositoryPort.save(user);

        // Notificações de e-mail são “extensões” plugáveis (não quebram a rota se falhar)
        try {
            if (!wasPasswordSetBefore) {
                passwordSetEmailService.sendFirstDefinition(user.getEmail(), user.getName());
            } else {
                passwordSetEmailService.sendChange(user.getEmail(), user.getName());
            }
        } catch (Exception ex) {
            log.warn("[PASSWORD EMAIL WARN] {}", ex.getMessage());
        }

        return ResponseEntity.ok(new MessageResponse(
                wasPasswordSetBefore ? "Password changed successfully" : "Password set successfully"
        ));
    }

    // ===================== PROFILE =====================
    @GetMapping(value = "/profile", produces = CT_JSON)
    public ResponseEntity<?> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Not authenticated"));
        }

        var user = userRepositoryPort.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String provider = user.getAuthProvider();
        if (provider == null || provider.trim().isEmpty()) {
            provider = "LOCAL";
        }

        var profile = new ProfileResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                provider,           // nunca null
                user.isPasswordSet()
        );

        return ResponseEntity.ok(profile);
    }

    // ===================== REFRESH TOKEN =====================
    @PostMapping(value = "/refresh-token", produces = CT_JSON)
    public ResponseEntity<?> refresh(
            @CookieValue(name = COOKIE_REFRESH, required = false) String refreshCookie,
            @CookieValue(name = COOKIE_CSRF, required = false) String csrfCookie,
            @RequestHeader(name = HDR_CSRF, required = false) String csrfHeader,
            HttpServletResponse response
    ) {
        if (refreshCookie == null || refreshCookie.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Missing refresh cookie"));
        }
        // Double-submit CSRF
        if (!csrfTokenService.validateCsrfToken(csrfHeader, csrfCookie)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Invalid CSRF token"));
        }
        if (!refreshTokenService.validate(refreshCookie)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }

        String email = refreshTokenService.getEmailByToken(refreshCookie);

        // ✅ Rotaciona o refresh + gera novo CSRF
        var rotated = refreshTokenService.rotate(email, refreshCookie);
        String newCsrf = csrfTokenService.generateCsrfToken(email);

        // Regrava cookies (refresh httpOnly + csrf legível)
        setAuthCookies(response, rotated.getToken(), newCsrf);
        exposeCsrfHeader(response, newCsrf);

        // depois (idêntico ao “antes” se você já trocou o DTO)
        String newAccess = jwtService.generateAccessToken(email);
        return ResponseEntity.ok(new AccessResponse(newAccess));
    }

    // ===================== FIND USER =====================
    @GetMapping(value = "/find-user", produces = CT_JSON)
    public ResponseEntity<?> findUser(
            @RequestParam
            @Email(message = "Invalid e-mail")
            @Pattern(
                    regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain")
            String email) {

        String normalized = email.trim().toLowerCase();
        return userService.findByEmail(normalized)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(new MessageResponse("User found: " + u.getEmail())))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found")));
    }

    // ===================== LOGOUT =====================
    @PostMapping(value = "/logout", produces = CT_JSON)
    public ResponseEntity<MessageResponse> logout(
            @CookieValue(name = COOKIE_REFRESH, required = false) String refreshCookie,
            HttpServletResponse response
    ) {
        if (refreshCookie != null && !refreshCookie.isBlank()) {
            try {
                refreshTokenService.revokeToken(refreshCookie);
            } catch (Exception ex) {
                log.warn("[LOGOUT] revoke failed: {}", ex.getMessage());
            }
        }
        clearAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    // ===================== Reenviar confirmação =====================
    @PostMapping(value = "/confirm/resend", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<MessageResponse> resendConfirmation(@Valid @RequestBody ForgotPasswordRequest req) {
        String email = req.email().trim().toLowerCase();
        var userOpt = userRepositoryPort.findByEmail(email);

        // Se usuário já confirmou o e-mail, bloqueia novo envio
        if (userOpt.isPresent() && userOpt.get().isEmailConfirmed()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new MessageResponse("Account already confirmed. Please log in."));
        }

        try {
            accountConfirmationService.requestConfirmation(email, frontendBaseUrl);
        } catch (Exception e) {
            log.warn("[CONFIRM RESEND WARN] {}", e.getMessage());
        }

        return ResponseEntity.ok(new MessageResponse(
                "If an account exists for this e-mail, we have sent a new confirmation link."
        ));
    }

    // ===================== Email está confirmado? =====================
    @GetMapping(value = "/confirmed", produces = CT_JSON)
    public ResponseEntity<?> isEmailConfirmed(
            @RequestParam
            @Email(message = "Invalid e-mail")
            @Pattern(
                    regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain")
            String email
    ) {
        String normalized = email.trim().toLowerCase();
        return userRepositoryPort.findByEmail(normalized)
                .map(user -> ResponseEntity.ok(new MessageResponse(
                        user.isEmailConfirmed()
                                ? "confirmed"
                                : "not_confirmed"
                )))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found")));
    }

    // ===================== Confirmar conta =====================
    @PostMapping(value = "/confirm-account", produces = CT_JSON)
    public ResponseEntity<MessageResponse> confirmAccount(@RequestParam("token") String token) {
        try {
            accountConfirmationService.confirm(token);
            return ResponseEntity.ok(new MessageResponse("E-mail confirmed successfully"));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse(ex.getMessage() == null
                            ? "Invalid or expired confirmation link"
                            : ex.getMessage()));
        } catch (Exception ex) {
            String id = UUID.randomUUID().toString();
            log.error("[CONFIRM ERROR {}] {}", id, ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error. Code: " + id));
        }
    }
}
