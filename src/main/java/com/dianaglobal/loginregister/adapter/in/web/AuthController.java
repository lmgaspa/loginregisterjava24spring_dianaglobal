package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.*;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.login.LoginResponse;
import com.dianaglobal.loginregister.adapter.in.dto.password.RegisterRequest;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.*;
import com.dianaglobal.loginregister.domain.model.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    private final RegisterUserUseCase registerService;
    private final UserService userService;
    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final AccountConfirmationService accountConfirmationService;

    @Value("${application.frontend.base-url}")
    private String frontendBaseUrl;

    @PostMapping(value = "/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> register(@RequestBody @Valid RegisterRequest request) {
        final String name = request.name().trim();
        final String email = request.email().trim().toLowerCase();
        final String password = request.password();

        try {
            registerService.register(name, email, password);

            // Envia o e-mail de confirmação apenas no cadastro
            accountConfirmationService.requestConfirmation(email, frontendBaseUrl);

            URI location = URI.create("/api/auth/find-user?email=" + email);
            return ResponseEntity.created(location)
                    .header(HttpHeaders.LOCATION, location.toString())
                    .body(new MessageResponse("User registered. Please check your e-mail to confirm your account."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new MessageResponse("E-mail is already registered"));
        } catch (Exception e) {
            String id = java.util.UUID.randomUUID().toString();
            System.err.println("[REGISTER ERROR " + id + "] " + e.getMessage());
            e.printStackTrace();
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

        // Bloqueia login enquanto não confirmar o e-mail (sem reenvio automático aqui)
        if (!user.isEmailConfirmed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Please confirm your e-mail before logging in."));
        }

        String jwt = jwtService.generateToken(user.getEmail());
        String refreshToken = refreshTokenService.create(user.getEmail()).getToken();

        return ResponseEntity.ok(new LoginResponse(jwt, refreshToken));
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

    // ====== CONFIRMAÇÃO DE CONTA ======

    /** Resend: chamado apenas quando o frontend disser que “não chegou o e-mail”. */
    @PostMapping(value = "/confirm/resend", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> resendConfirm(@RequestBody @Valid ResendConfirmRequest body) {
        final String email = body.email().trim().toLowerCase();
        // Não vaza existência: dispara para existentes, ignora se não existir.
        accountConfirmationService.requestConfirmation(email, frontendBaseUrl);
        return ResponseEntity.ok(new MessageResponse("If the e-mail exists, we’ve sent a new confirmation link."));
    }

    /** Verify: confirma conta via token recebido por e-mail. */
    @PostMapping(value = "/confirm/verify", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> verifyConfirm(@RequestBody @Valid ConfirmTokenRequest body) {
        accountConfirmationService.confirm(body.token());
        return ResponseEntity.ok(new MessageResponse("Account confirmed successfully."));
    }

    // records internos (sem criar novos arquivos)
    public record MessageResponse(String message) {}

    public record ResendConfirmRequest(
            @NotBlank
            @Email(message = "Invalid e-mail")
            @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain")
            String email
    ) {}

    public record ConfirmTokenRequest(@NotBlank String token) {}
}
