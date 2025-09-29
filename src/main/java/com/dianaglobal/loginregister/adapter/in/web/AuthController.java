// src/main/java/com/dianaglobal/loginregister/adapter/in/web/AuthController.java
package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.*;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.JwtService;
import com.dianaglobal.loginregister.application.service.RefreshTokenService;
import com.dianaglobal.loginregister.application.service.UserService;
import com.dianaglobal.loginregister.domain.model.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
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

    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(@RequestBody @Valid RegisterRequest request) {
        // Normalize inputs early
        final String name = request.name().trim();
        final String email = request.email().trim().toLowerCase();
        final String password = request.password();

        registerService.register(name, email, password);

        // 201 + Location (points to a simple lookup)
        URI location = URI.create("/api/auth/find-user?email=" + email);
        return ResponseEntity.created(location)
                .headers(h -> h.add(HttpHeaders.LOCATION, location.toString()))
                .body(new MessageResponse("User successfully registered"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest request) {
        var userOpt = userRepositoryPort.findByEmail(request.email().trim().toLowerCase());
        if (userOpt.isEmpty()) {
            // do not leak which part failed
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        }
        var user = userOpt.get();
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        }

        String jwt = jwtService.generateToken(user.getEmail());
        String refreshToken = refreshTokenService.create(user.getEmail()).getToken();
        return ResponseEntity.ok(new LoginResponse(jwt, refreshToken));
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Not authenticated"));
        }
        User user = userRepositoryPort.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return ResponseEntity.ok(new ProfileResponseDTO(user.getId(), user.getName(), user.getEmail()));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refresh(@RequestBody @Valid RefreshRequestDTO body) {
        if (!refreshTokenService.validate(body.refreshToken())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }
        String email = refreshTokenService.getEmailByToken(body.refreshToken());
        String newToken = jwtService.generateToken(email);
        return ResponseEntity.ok(new JwtResponse(newToken));
    }

    @GetMapping("/find-user")
    public ResponseEntity<?> findUser(
            @RequestParam
            @Email(message = "Invalid e-mail")
            @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain/TLD")
            String email) {

        String normalized = email.trim().toLowerCase();
        return userService.findByEmail(normalized)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(new MessageResponse("User found: " + u.getEmail())))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found")));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@RequestBody @Valid RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    @PostMapping("/revoke-refresh")
    public ResponseEntity<MessageResponse> revokeRefresh(@RequestBody @Valid RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok(new MessageResponse("Refresh token revoked"));
    }

    // Small, reusable message DTO
    public record MessageResponse(String message) {}
}
