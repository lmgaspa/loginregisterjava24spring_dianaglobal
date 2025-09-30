package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.JwtResponse;
import com.dianaglobal.loginregister.adapter.in.dto.OAuthGoogleRequest;
import com.dianaglobal.loginregister.adapter.in.dto.ProfileResponseDTO;
import com.dianaglobal.loginregister.adapter.in.dto.RefreshRequestDTO;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginResponse;
import com.dianaglobal.loginregister.adapter.in.dto.password.ForgotPasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.password.RegisterRequest;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.*;
import com.dianaglobal.loginregister.domain.model.User;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
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
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    private final RegisterUserUseCase registerService;
    private final AccountConfirmationService accountConfirmationService;
    private final UserService userService;
    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    // ✅ Necessário para o fluxo OAuth (registra/garante usuário Google)
    private final RegisterUserService registerUserService;

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    // Mensagem simples
    public record MessageResponse(String message) {}

    // Bean opcional (só existe quando google.oauth.enabled=true)
    @Autowired(required = false)
    private GoogleIdTokenVerifier googleTokenVerifier;

    @PostMapping(value = "/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> register(@RequestBody @Valid RegisterRequest request) {
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

    @PostMapping(value = "/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest request) {
        var userOpt = userRepositoryPort.findByEmail(request.email().trim().toLowerCase());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        }

        User user = userOpt.get();
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        }

        if (!user.isEmailConfirmed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Please confirm your e-mail to sign in"));
        }

        String jwt = jwtService.generateToken(user.getEmail());
        String refreshToken = refreshTokenService.create(user.getEmail()).getToken();

        return ResponseEntity.ok(new LoginResponse(jwt, refreshToken));
    }

    /**
     * Endpoint idempotente para Google OAuth.
     * Verifica o ID token do Google, garante/cria o usuário e retorna JWT + refresh do seu backend.
     */
    @PostMapping(value = "/oauth/google", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> oauthWithGoogle(@RequestBody @Valid OAuthGoogleRequest req) {
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

            var userOpt = userRepositoryPort.findByEmail(email);
            User user;
            if (userOpt.isPresent()) {
                user = userOpt.get();
            } else {
                // Cria usuário já confirmado para OAuth
                registerUserService.registerOauthUser(name, email, sub);
                user = userRepositoryPort.findByEmail(email)
                        .orElseThrow(() -> new IllegalStateException("User creation failed"));
            }

            if (!user.isEmailConfirmed()) {
                user.setEmailConfirmed(true);
                userRepositoryPort.save(user);
            }

            String jwt = jwtService.generateToken(user.getEmail());
            String refreshToken = refreshTokenService.create(user.getEmail()).getToken();

            return ResponseEntity.ok(new LoginResponse(jwt, refreshToken));
        } catch (Exception e) {
            log.error("[GOOGLE OAUTH ERROR] {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error"));
        }
    }

    @GetMapping(value = "/profile", produces = "application/json")
    public ResponseEntity<?> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Not authenticated"));
        }

        User user = userRepositoryPort.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return ResponseEntity.ok(new ProfileResponseDTO(user.getId(), user.getName(), user.getEmail()));
    }

    @PostMapping(value = "/refresh-token", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> refresh(@RequestBody @Valid RefreshRequestDTO body) {
        if (!refreshTokenService.validate(body.refreshToken())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }
        String email = refreshTokenService.getEmailByToken(body.refreshToken());
        String newToken = jwtService.generateToken(email);
        return ResponseEntity.ok(new JwtResponse(newToken));
    }

    @GetMapping(value = "/find-user", produces = "application/json")
    public ResponseEntity<?> findUser(
            @RequestParam
            @Email(message = "Invalid e-mail")
            @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain")
            String email) {

        String normalized = email.trim().toLowerCase();
        return userService.findByEmail(normalized)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(new MessageResponse("User found: " + u.getEmail())))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found")));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/logout", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> logout(@RequestBody @Valid RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    @PostMapping(value = "/revoke-refresh", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> revokeRefresh(@RequestBody @Valid RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok(new MessageResponse("Refresh token revoked"));
    }

    @PostMapping(value = "/confirm-account", produces = "application/json")
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

    /** Reenvia link de confirmação sem vazar existência de e-mail. */
    @PostMapping(value = "/confirm/resend", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> resendConfirmation(@Valid @RequestBody ForgotPasswordRequest req) {
        try {
            accountConfirmationService.requestConfirmation(req.email(), frontendBaseUrl);
        } catch (Exception e) {
            log.warn("[CONFIRM RESEND WARN] {}", e.getMessage());
        }
        return ResponseEntity.ok(new MessageResponse(
                "If an account exists for this e-mail, we have sent a new confirmation link."
        ));
    }
}
