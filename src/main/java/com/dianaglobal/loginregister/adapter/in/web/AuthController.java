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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<String> register(@RequestBody @Valid RegisterRequest request) {
        registerService.register(request.name(), request.email(), request.password());
        return ResponseEntity.ok("User successfully registered");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        var user = userRepositoryPort.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String jwt = jwtService.generateToken(user.getEmail());
        String refreshToken = refreshTokenService.create(user.getEmail()).getToken();

        return ResponseEntity.ok(new LoginResponse(jwt, refreshToken));
    }

    @GetMapping("/profile")
    public ResponseEntity<ProfileResponseDTO> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepositoryPort.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(new ProfileResponseDTO(user.getId(), user.getName(), user.getEmail()));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtResponse> refresh(@RequestBody @Valid RefreshRequestDTO body) {
        if (!refreshTokenService.validate(body.refreshToken())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String email = refreshTokenService.getEmailByToken(body.refreshToken());
        String newToken = jwtService.generateToken(email);
        return ResponseEntity.ok(new JwtResponse(newToken));
    }

    @GetMapping("/find-user")
    public ResponseEntity<String> findUser(
            @RequestParam
            @Email(message = "Invalid e-mail")
            @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain/TLD")
            String email) {
        return userService.findByEmail(email.trim().toLowerCase())
                .map(u -> ResponseEntity.ok("User found: " + u.getEmail()))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found"));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody @Valid RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/revoke-refresh")
    public ResponseEntity<String> revokeRefresh(@RequestBody @Valid RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok("Refresh token revoked.");
    }
}
