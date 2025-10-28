package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.ApiError;
import com.dianaglobal.loginregister.adapter.in.dto.JwtResponse;
import com.dianaglobal.loginregister.adapter.in.dto.OAuthGoogleRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginResponse;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.ConfirmationResendThrottleService;
import com.dianaglobal.loginregister.application.service.JwtService;
import com.dianaglobal.loginregister.application.service.RefreshTokenService;
import com.dianaglobal.loginregister.domain.model.User;
import com.dianaglobal.loginregister.security.AuthenticationCookieHelper;
import com.dianaglobal.loginregister.security.CsrfTokenService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthenticationController {

    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final CsrfTokenService csrfTokenService;
    private final ConfirmationResendThrottleService confirmationResendThrottleService;
    private final AuthenticationCookieHelper cookieHelper;

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    @Autowired(required = false)
    private GoogleIdTokenVerifier googleTokenVerifier;

    public record MessageResponse(String message) {}

    // ===================== LOGIN (password) =====================
    @PostMapping(value = "/login", consumes = "application/json", produces = "application/json")
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
            var info = confirmationResendThrottleService.preview(user.getId(), java.time.Instant.now());
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

        cookieHelper.setAuthCookies(response, refresh, csrf);
        cookieHelper.exposeCsrfHeader(response, csrf);

        return ResponseEntity.ok(new LoginResponse(access, null));
    }

    // ===================== LOGIN (Google OAuth) =====================
    @PostMapping(value = "/oauth/google", consumes = "application/json", produces = "application/json")
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
            // TODO: Mover registro OAuth para RegistrationController
            // Por enquanto mantenho aqui para não quebrar funcionalidade
            User user = createOrUpdateOAuthUser(name, email, sub);

            String access = jwtService.generateToken(user.getEmail());
            var refreshModel = refreshTokenService.create(user.getEmail());
            String refresh = refreshModel.getToken();
            String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

            cookieHelper.setAuthCookies(response, refresh, csrf);
            cookieHelper.exposeCsrfHeader(response, csrf);

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

    // TODO: Mover este método para RegistrationController
    private User createOrUpdateOAuthUser(String name, String email, String sub) {
        var existing = userRepositoryPort.findByEmail(email);
        if (existing.isPresent()) {
            User u = existing.get();
            if (!u.isEmailConfirmed()) {
                u.setEmailConfirmed(true);
            }
            if (u.getAuthProvider() == null) {
                u.setAuthProvider("GOOGLE");
            }
            if (u.getPassword() == null || u.getPassword().trim().isEmpty()) {
                u.setPasswordSet(false);
            }
            userRepositoryPort.save(u);
            return u;
        }

        User u = User.builder()
                .id(UUID.randomUUID())
                .name(name == null ? null : name.trim())
                .email(email)
                .password(UUID.randomUUID().toString())
                .emailConfirmed(true)
                .passwordSet(false)
                .authProvider("GOOGLE")
                .build();

        userRepositoryPort.save(u);
        return u;
    }

    // ===================== REFRESH TOKEN =====================
    @PostMapping(value = "/refresh-token", produces = "application/json")
    public ResponseEntity<?> refresh(
            @CookieValue(name = "refresh_token", required = false) String refreshCookie,
            @CookieValue(name = "csrf_token", required = false) String csrfCookie,
            @RequestHeader(name = "X-CSRF-Token", required = false) String csrfHeader,
            HttpServletResponse response
    ) {
        if (refreshCookie == null || refreshCookie.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Missing refresh cookie"));
        }

        if (!refreshTokenService.validate(refreshCookie)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }

        String email = refreshTokenService.getEmailByToken(refreshCookie);
        var rotated = refreshTokenService.rotate(email, refreshCookie);
        String newCsrf = csrfTokenService.generateCsrfToken(email);

        cookieHelper.setAuthCookies(response, rotated.getToken(), newCsrf);
        cookieHelper.exposeCsrfHeader(response, newCsrf);

        String newAccess = jwtService.generateToken(email);
        return ResponseEntity.ok(new JwtResponse(newAccess));
    }

    // ===================== LOGOUT =====================
    @PostMapping(value = "/logout", produces = "application/json")
    public ResponseEntity<MessageResponse> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshCookie,
            HttpServletResponse response
    ) {
        if (refreshCookie != null && !refreshCookie.isBlank()) {
            try {
                refreshTokenService.revokeToken(refreshCookie);
            } catch (Exception ex) {
                log.warn("[LOGOUT] revoke failed: {}", ex.getMessage());
            }
        }
        cookieHelper.clearAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }
}

