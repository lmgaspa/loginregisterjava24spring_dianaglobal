package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.ApiError;
import com.dianaglobal.loginregister.adapter.in.dto.JwtResponse;
import com.dianaglobal.loginregister.adapter.in.dto.OAuthGoogleRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginResponse;
import com.dianaglobal.loginregister.adapter.in.dto.password.ForgotPasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.password.ResetPasswordRequest;
import com.dianaglobal.loginregister.adapter.in.web.util.AuthCookieUtil;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.*;
import com.dianaglobal.loginregister.config.ApiPaths;
import com.dianaglobal.loginregister.domain.model.User;
import com.dianaglobal.loginregister.security.CsrfTokenService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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
import java.time.Instant;
import java.util.Map;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.UUID;


@Slf4j
@RestController
@RequestMapping(ApiPaths.AUTH_BASE) // "/api/v1/auth"
@RequiredArgsConstructor
@Validated
public class SessionController {

    private final UserRepositoryPort userRepositoryPort;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CsrfTokenService csrfTokenService;
    private final RegisterUserUseCase registerService;
    private final ConfirmationResendThrottleService confirmationResendThrottleService;
    private final AccountConfirmationService accountConfirmationService;
    private final PasswordResetService passwordResetService;
    private final AuthCookieUtil authCookieUtil;

    @Autowired(required = false)
    private GoogleIdTokenVerifier googleTokenVerifier;

    // URL base do frontend (pra montar links nos e-mails de confirmação / reset)
    @Value("${application.frontend.base-url}")
    private String frontendBaseUrl;

    // ------------------------------------------------------------------------------------
    // LOGIN COM SENHA LOCAL
    // ------------------------------------------------------------------------------------
    @PostMapping(value = "/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletResponse response
    ) {

        var userOpt = userRepositoryPort.findByEmail(request.email().trim().toLowerCase());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        }
        User user = userOpt.get();

        // se a conta veio do Google e não tem password setado, exigir login social
        if ("GOOGLE".equalsIgnoreCase(user.getAuthProvider()) && !user.isPasswordSet()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Use Sign in with Google or set a password first."));
        }

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        }

        // e-mail não confirmado => erro tipado EMAIL_UNCONFIRMED + cooldown info
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

        // gerar tokens e CSRF
        String access = jwtService.generateToken(user.getEmail());
        var refreshModel = refreshTokenService.create(user.getEmail());
        String refresh = refreshModel.getToken();
        String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

        // setar cookies httpOnly + expor header do CSRF
        authCookieUtil.setAuthCookies(response, refresh, csrf);
        authCookieUtil.exposeCsrfHeader(response, csrf);

        return ResponseEntity.ok(new LoginResponse(access, null));
    }

    // ------------------------------------------------------------------------------------
    // LOGIN VIA GOOGLE OAUTH
    // ------------------------------------------------------------------------------------
    @PostMapping(value = "/oauth/google", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> oauthWithGoogle(
            @RequestBody @Valid OAuthGoogleRequest req,
            HttpServletResponse response
    ) {

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

            // coerência de provider e flag password
            if (user.getAuthProvider() == null || !"GOOGLE".equalsIgnoreCase(user.getAuthProvider())) {
                user.setAuthProvider("GOOGLE");
            }
            if (user.getPassword() == null || user.getPassword().isBlank()) {
                user.setPasswordSet(false);
            }
            userRepositoryPort.save(user);

            // gerar tokens
            String access = jwtService.generateToken(user.getEmail());
            var refreshModel = refreshTokenService.create(user.getEmail());
            String refresh = refreshModel.getToken();
            String csrf = csrfTokenService.generateCsrfToken(user.getEmail());

            authCookieUtil.setAuthCookies(response, refresh, csrf);
            authCookieUtil.exposeCsrfHeader(response, csrf);

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

    // ------------------------------------------------------------------------------------
    // REGISTRO (NOME + EMAIL + SENHA)
    // ------------------------------------------------------------------------------------
    public record RegisterRequest(
            @NotBlank String name,
            @NotBlank
            @Email(message = "Invalid e-mail")
            @Pattern(
                    regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain"
            )
            String email,
            @NotBlank String password
    ) {}

    @PostMapping(value = "/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest body) {
        try {
            final String normalizedEmail = body.email().trim().toLowerCase();

            // 1. já existe?
            var existing = userRepositoryPort.findByEmail(normalizedEmail);
            if (existing.isPresent()) {
                // conflito: e-mail já cadastrado
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new MessageResponse("This e-mail is already registered."));
            }

            // 2. montar novo usuário LOCAL
            User newUser = new User();
            newUser.setId(UUID.randomUUID());
            newUser.setName(body.name());
            newUser.setEmail(normalizedEmail);

            // senha hash
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setPasswordSet(true);

            // conta recém criada ainda NÃO confirmada
            newUser.setEmailConfirmed(false);

            // marca provedor local
            newUser.setAuthProvider("LOCAL");

            // se seu modelo tiver timestamps, etc., ajuste aqui:
            // newUser.setCreatedAt(Instant.now());
            // newUser.setUpdatedAt(Instant.now());

            userRepositoryPort.save(newUser);

            // 3. dispara e-mail de confirmação
            // usa o mesmo serviço que o fluxo de confirmação já usa
            accountConfirmationService.requestConfirmation(
                    normalizedEmail,
                    frontendBaseUrl
            );

            // 4. resposta "safe"
            return ResponseEntity.ok(
                    new MessageResponse(
                            "If this e-mail is valid, a confirmation link has been sent."
                    )
            );

        } catch (IllegalArgumentException ex) {
            // validação de domínio, etc.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse(ex.getMessage()));
        } catch (RuntimeException ex) {
            log.error("[REGISTER] error: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Could not register now."));
        }
    }


    // ------------------------------------------------------------------------------------
    // ESQUECI MINHA SENHA / RESET DE SENHA POR TOKEN
    // ------------------------------------------------------------------------------------
    @PostMapping(value = "/forgot-password", consumes = "application/json")
    public ResponseEntity<?> forgotPassword(@RequestBody @Valid ForgotPasswordRequest req) {
        // dispara e-mail com link /reset-password?token=...
        passwordResetService.requestReset(req.email(), frontendBaseUrl);
        return ResponseEntity.noContent().build(); // 204
    }

    @PostMapping(value = "/reset-password", consumes = "application/json")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid ResetPasswordRequest req) {
        // valida token e troca a senha
        passwordResetService.resetPassword(req.token(), req.newPassword());
        return ResponseEntity.ok().build();
    }

    // ------------------------------------------------------------------------------------
    // REENVIAR E-MAIL DE CONFIRMAÇÃO (COOLDOWN / LIMITES)
    // ------------------------------------------------------------------------------------
    public record ResendConfirmRequest(
            @NotBlank
            @Email(message = "Invalid e-mail")
            @Pattern(
                    regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain"
            )
            String email,

            // opcional: o front pode mandar uma baseUrl diferente
            String frontendBaseUrl
    ) {}

    @PostMapping(value = "/confirm/resend", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> resendConfirm(@RequestBody @Valid ResendConfirmRequest body) {
        Instant now = Instant.now();

        // escolhe qual baseURL vamos usar no link
        String feBase = (body.frontendBaseUrl() != null && !body.frontendBaseUrl().isBlank())
                ? body.frontendBaseUrl()
                : frontendBaseUrl;

        var result = accountConfirmationService.resendWithThrottle(
                body.email().trim().toLowerCase(),
                feBase,
                now
        );

        // esse service já retorna status HTTP e body padronizado
        return ResponseEntity
                .status(result.httpStatus())
                .body(result.body());
    }

    // ------------------------------------------------------------------------------------
    // CONSULTAR STATUS DE CONFIRMAÇÃO (usado na /check-email do front)
    // GET /api/v1/auth/confirmed?email=foo@bar.com
    // ------------------------------------------------------------------------------------
    @GetMapping(value = "/confirmed", produces = "application/json")
    public ResponseEntity<?> confirmedStatus(
            @RequestParam("email") String email
    ) {
        var opt = userRepositoryPort.findByEmail(email.trim().toLowerCase());
        if (opt.isEmpty()) {
            // não revela se existe ou não, mas mantemos shape previsível
            return ResponseEntity.ok(Map.of(
                    "confirmed", false,
                    "status", "unknown"
            ));
        }
        User u = opt.get();
        boolean confirmed = u.isEmailConfirmed();
        return ResponseEntity.ok(Map.of(
                "confirmed", confirmed,
                "status", confirmed ? "confirmed" : "pending"
        ));
    }

    // ------------------------------------------------------------------------------------
    // REFRESH TOKEN
    // Front manda cookie refresh_token + header X-CSRF-Token
    // ------------------------------------------------------------------------------------
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

        // validação de CSRF: header tem que bater com cookie
        if (!csrfTokenService.validateCsrfToken(csrfHeader, csrfCookie)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Invalid CSRF token"));
        }

        if (!refreshTokenService.validate(refreshCookie)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }

        String email = refreshTokenService.getEmailByToken(refreshCookie);

        // gira o refresh (revoga o antigo e cria um novo)
        var rotated = refreshTokenService.rotate(email, refreshCookie);

        // gera novo CSRF
        String newCsrf = csrfTokenService.generateCsrfToken(email);

        // atualiza cookies httpOnly e expõe header com o novo CSRF
        authCookieUtil.setAuthCookies(response, rotated.getToken(), newCsrf);
        authCookieUtil.exposeCsrfHeader(response, newCsrf);

        // devolve novo access token (JWT curto)
        String newAccess = jwtService.generateToken(email);
        return ResponseEntity.ok(new JwtResponse(newAccess));
    }

    // ------------------------------------------------------------------------------------
    // LOGOUT
    // ------------------------------------------------------------------------------------
    @PostMapping(value = "/logout", produces = "application/json")
    public ResponseEntity<MessageResponse> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshCookie,
            @CookieValue(name = "csrf_token", required = false) String csrfCookie,
            @RequestHeader(name = "X-CSRF-Token", required = false) String csrfHeader,
            HttpServletResponse response
    ) {
        // protege contra CSRF: header <-> cookie
        if (!csrfTokenService.validateCsrfToken(csrfHeader, csrfCookie)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Invalid CSRF token"));
        }

        // revoga refresh
        if (refreshCookie != null && !refreshCookie.isBlank()) {
            try {
                refreshTokenService.revokeToken(refreshCookie);
            } catch (Exception ex) {
                log.warn("[LOGOUT] revoke failed: {}", ex.getMessage());
            }
        }

        // limpa cookies no browser
        authCookieUtil.clearAuthCookies(response);

        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    // ------------------------------------------------------------------------------------
    // Pequeno DTO "genérico" de mensagem
    // ------------------------------------------------------------------------------------
    public record MessageResponse(String message) {}
}
