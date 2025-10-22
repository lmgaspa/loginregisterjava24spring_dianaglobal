package com.dianaglobal.loginregister.adapter.in.web;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

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
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dianaglobal.loginregister.adapter.in.dto.ApiError;
import com.dianaglobal.loginregister.adapter.in.dto.JwtResponse;
import com.dianaglobal.loginregister.adapter.in.dto.OAuthGoogleRequest;
import com.dianaglobal.loginregister.adapter.in.dto.ProfileResponseDTO;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginResponse;
import com.dianaglobal.loginregister.adapter.in.dto.password.ChangePasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.password.ForgotPasswordRequest;
import com.dianaglobal.loginregister.adapter.out.mail.PasswordSetEmailService;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.AccountConfirmationService;
import com.dianaglobal.loginregister.application.service.ConfirmationResendThrottleService;
import com.dianaglobal.loginregister.application.service.EmailChangeService;
import com.dianaglobal.loginregister.application.service.JwtService;
import com.dianaglobal.loginregister.application.service.RefreshTokenService;
import com.dianaglobal.loginregister.application.service.UserService;
import com.dianaglobal.loginregister.domain.model.User;
import com.dianaglobal.loginregister.security.CsrfTokenService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    // ======== Constantes ========
    private static final String HDR_SET_COOKIE = HttpHeaders.SET_COOKIE;
    private static final String HDR_EXPOSE = "Access-Control-Expose-Headers";
    private static final String HDR_CSRF = "X-CSRF-Token";
    private static final String CT_JSON = "application/json";
    private static final String COOKIE_REFRESH = "refresh_token";
    private static final String COOKIE_CSRF = "csrf_token";
    private static final String COOKIE_PATH = "/api/auth";
    private static final String SAME_SITE_NONE = "None";
    private static final String SAME_SITE_LAX = "Lax";

    // ======== Serviços ========
    private final RegisterUserUseCase registerService;
    private final AccountConfirmationService accountConfirmationService;
    private final UserService userService;
    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final CsrfTokenService csrfTokenService;
    private final PasswordSetEmailService passwordSetEmailService;
    private final ConfirmationResendThrottleService confirmationResendThrottleService;
    private final EmailChangeService emailChangeService; // NEW

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    @Value("${application.cookies.secure:true}")
    private boolean cookiesSecure;

    @Value("${application.auth.refresh-ttl-days:30}")
    private long refreshTtlDays;

    public record MessageResponse(String message) {}

    @Autowired(required = false)
    private GoogleIdTokenVerifier googleTokenVerifier;

    // ===================== Helpers de cookie/headers =====================
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
                .httpOnly(false)
                .secure(cookiesSecure)
                .sameSite(sameSite)
                .path(COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .build();
    }

    private void setAuthCookies(HttpServletResponse response, String refresh, String csrf) {
        long maxAge = Duration.ofDays(refreshTtlDays).getSeconds();
        ResponseCookie refreshCookie = buildRefreshCookie(refresh, maxAge, SAME_SITE_NONE);
        ResponseCookie csrfCookie    = buildCsrfCookie(csrf, maxAge, SAME_SITE_NONE);
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
    public ResponseEntity<MessageResponse> register(
            @RequestBody @Valid com.dianaglobal.loginregister.adapter.in.dto.password.RegisterRequest request) {

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

        // E-mail não confirmado => erro tipado + metadados de cooldown
        if (!user.isEmailConfirmed()) {
            var info = confirmationResendThrottleService.preview(user.getId(), Instant.now());
            var body = ApiError.builder()
                    .error("EMAIL_UNCONFIRMED")
                    .message("Unconfirmed email.")
                    .canResend(info.canResend())
                    .cooldownSecondsRemaining(info.cooldownSecondsRemaining())
                    .attemptsToday(info.attemptsToday())
                    .maxPerDay(info.maxPerDay())
                    .nextAllowedAt(info.nextAllowedAt())
                    .build();
            return ResponseEntity.status(HttpStatus.CONFLICT).body(body); // 409
        }

        String access = jwtService.generateToken(user.getEmail());
        var refreshModel = refreshTokenService.create(user.getEmail());
        String refresh = refreshModel.getToken();
        String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

        setAuthCookies(response, refresh, csrf);
        exposeCsrfHeader(response, csrf);

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

            // Provider/flags
            String provider = user.getAuthProvider();
            if (provider == null || !"GOOGLE".equalsIgnoreCase(provider)) {
                user.setAuthProvider("GOOGLE");
            }
            if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
                user.setPasswordSet(false);
            }
            userRepositoryPort.save(user);

            String access = jwtService.generateToken(user.getEmail());
            var refreshModel = refreshTokenService.create(user.getEmail());
            String refresh = refreshModel.getToken();
            String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

            setAuthCookies(response, refresh, csrf);
            exposeCsrfHeader(response, csrf);

            return ResponseEntity.ok(new LoginResponse(access, null));
        } catch (GeneralSecurityException e) {
            log.error("[GOOGLE OAUTH ERROR] Security error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid Google token"));
        } catch (IOException e) {
            log.error("[GOOGLE OAUTH ERROR] IO error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Token verification failed"));
        } catch (IllegalArgumentException e) {
            log.error("[GOOGLE OAUTH ERROR] Validation error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse(e.getMessage()));
        } catch (DuplicateKeyException e) {
            log.error("[GOOGLE OAUTH ERROR] Duplicate key error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new MessageResponse("Account already exists"));
        } catch (RuntimeException e) {
            log.error("[GOOGLE OAUTH ERROR] Runtime error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error"));
        }
    }

    // ===================== SET PASSWORD =====================
    public record NewPasswordDTO(
            @jakarta.validation.constraints.NotBlank(message = "Password cannot be blank")
            @jakarta.validation.constraints.Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
            @jakarta.validation.constraints.Pattern(
                    regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).{8,}$",
                    message = "Password must include at least 1 uppercase letter, 1 lowercase letter, and 1 digit and be at least 8 characters"
            ) String newPassword
    ) {}

    @PostMapping(value = "/password/set", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<?> setPassword(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid NewPasswordDTO body,
            @RequestHeader(name = "Authorization", required = false) String authHeader
    ) {
        // Log da tentativa de alteração de senha para auditoria
        String requestId = UUID.randomUUID().toString();
        log.info("[PASSWORD SET REQUEST {}] Attempt to set password for user: {}", 
                requestId, principal != null ? principal.getUsername() : "unknown");
        
        // Debug: Log do header de autorização
        log.info("[PASSWORD SET DEBUG {}] Auth header: {}", requestId, authHeader != null ? "present" : "missing");

        // Verificação de autenticação
        if (principal == null) {
            log.warn("[PASSWORD SET ERROR {}] Authentication failed - no principal", requestId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Not authenticated"));
        }

        try {
            // Buscar usuário
            var user = userRepositoryPort.findByEmail(principal.getUsername());
            if (user.isEmpty()) {
                log.warn("[PASSWORD SET ERROR {}] User not found: {}", requestId, principal.getUsername());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found"));
            }

            User userEntity = user.get();
            final boolean wasPasswordSetBefore = userEntity.isPasswordSet();

            // Validar senha adicional (além da validação do Bean Validation)
            String newPassword = body.newPassword();
            if (newPassword == null || newPassword.trim().isEmpty()) {
                log.warn("[PASSWORD SET ERROR {}] Empty password provided for user: {}", requestId, userEntity.getEmail());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new MessageResponse("Password cannot be empty"));
            }

            // Verificar se a nova senha é diferente da atual (se já existe)
            if (wasPasswordSetBefore && passwordEncoder.matches(newPassword, userEntity.getPassword())) {
                log.warn("[PASSWORD SET ERROR {}] New password same as current password for user: {}", requestId, userEntity.getEmail());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new MessageResponse("New password must be different from current password"));
            }

            // Fazer hash da nova senha
            String hashedPassword = passwordEncoder.encode(newPassword);
            userEntity.setPassword(hashedPassword);
            userEntity.setPasswordSet(true);
            userRepositoryPort.save(userEntity);

            // Log de sucesso para auditoria
            log.info("[PASSWORD SET SUCCESS {}] Password {} for user: {}", 
                    requestId, wasPasswordSetBefore ? "changed" : "set", userEntity.getEmail());

            // Enviar email de notificação
            try {
                if (!wasPasswordSetBefore) {
                    passwordSetEmailService.sendFirstDefinition(userEntity.getEmail(), userEntity.getName());
                } else {
                    passwordSetEmailService.sendChange(userEntity.getEmail(), userEntity.getName());
                }
            } catch (Exception ex) {
                log.warn("[PASSWORD SET EMAIL WARN {}] Failed to send notification email: {}", requestId, ex.getMessage());
            }

            return ResponseEntity.ok(new MessageResponse(
                    wasPasswordSetBefore ? "Password changed successfully" : "Password set successfully"
            ));

        } catch (IllegalArgumentException e) {
            log.error("[PASSWORD SET ERROR {}] Validation error: {}", requestId, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("[PASSWORD SET ERROR {}] Unexpected error: {}", requestId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal server error"));
        }
    }

    // ===================== EMAIL CHANGE (request/confirm) =====================
    public record ChangeEmailRequest(
            @Email(message="Invalid e-mail")
            @Pattern(regexp="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message="E-mail must contain a valid domain")
            String newEmail
    ) {}

    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/email/change-request", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<MessageResponse> requestEmailChange(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid ChangeEmailRequest req) {

        var user = userRepositoryPort.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        emailChangeService.requestChange(user.getId(), req.newEmail().trim().toLowerCase(), frontendBaseUrl);
        return ResponseEntity.ok(new MessageResponse("We sent a confirmation link to your new e-mail."));
    }

    // (ÚNICO endpoint para GET/POST)
    @RequestMapping(
            value = "/email/change-confirm",
            method = { RequestMethod.GET, RequestMethod.POST },
            produces = CT_JSON
    )
    public ResponseEntity<MessageResponse> confirmEmailChange(@RequestParam("token") String token) {
        emailChangeService.confirm(token);
        return ResponseEntity.ok(new MessageResponse("E-mail changed successfully"));
    }

    // ===================== PASSWORD CHANGE (autenticado) =====================
    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/password/change", consumes = CT_JSON, produces = CT_JSON)
    public ResponseEntity<MessageResponse> changePassword(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid ChangePasswordRequest body) {

        var user = userRepositoryPort.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordEncoder.matches(body.currentPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Current password is incorrect"));
        }

        user.setPassword(passwordEncoder.encode(body.newPassword()));
        user.setPasswordSet(true);
        userRepositoryPort.save(user);

        try { passwordSetEmailService.sendChange(user.getEmail(), user.getName()); } catch (Exception ignored) {}

        return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
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
                provider,
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
        // Temporariamente desabilitado para debug
        // if (!csrfTokenService.validateCsrfToken(csrfHeader, csrfCookie)) {
        //     return ResponseEntity.status(HttpStatus.FORBIDDEN)
        //             .body(new MessageResponse("Invalid CSRF token"));
        // }
        if (!refreshTokenService.validate(refreshCookie)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }

        String email = refreshTokenService.getEmailByToken(refreshCookie);
        var rotated = refreshTokenService.rotate(email, refreshCookie);
        String newCsrf = csrfTokenService.generateCsrfToken(email);

        setAuthCookies(response, rotated.getToken(), newCsrf);
        exposeCsrfHeader(response, newCsrf);

        String newAccess = jwtService.generateToken(email);
        return ResponseEntity.ok(new JwtResponse(newAccess));
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
                        user.isEmailConfirmed() ? "confirmed" : "not_confirmed"
                )))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found")));
    }

    // ===================== Confirmar conta (GET/POST) =====================
    @RequestMapping(
            value = "/confirm-account",
            method = { RequestMethod.GET, RequestMethod.POST },
            produces = CT_JSON
    )
    public ResponseEntity<MessageResponse> confirmAccount(@RequestParam("token") String token) {
        try {
            accountConfirmationService.confirm(token);
            return ResponseEntity.ok(new MessageResponse("E-mail confirmed successfully"));
        } catch (IllegalArgumentException ex) {
            String msg = (ex.getMessage() == null || ex.getMessage().isBlank())
                    ? "Invalid or expired confirmation link"
                    : ex.getMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse(msg));
        } catch (Exception ex) {
            String id = UUID.randomUUID().toString();
            log.error("[CONFIRM ERROR {}] {}", id, ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error. Code: " + id));
        }
    }
}
