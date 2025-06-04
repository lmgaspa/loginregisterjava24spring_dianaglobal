package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.*;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.RefreshTokenService;
import com.dianaglobal.loginregister.application.service.UserService;
import com.dianaglobal.loginregister.application.service.JwtService;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RegisterUserUseCase registerService;
    private final UserService userService;
    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        registerService.register(request.name(), request.email(), request.password());
        return ResponseEntity.ok("User successfully registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        var user = userRepositoryPort.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
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
    public ResponseEntity<JwtResponse> refresh(@RequestBody RefreshRequestDTO body) {
        if (!refreshTokenService.validate(body.refreshToken())) {
            return ResponseEntity.status(401).build();
        }

        String email = refreshTokenService.getEmailByToken(body.refreshToken());
        String newToken = jwtService.generateToken(email);

        return ResponseEntity.ok(new JwtResponse(newToken));
    }

    @GetMapping("/find-user")
    public ResponseEntity<?> findUser(@RequestParam String email) {
        return userService.findByEmail(email)
                .map(user -> ResponseEntity.ok("User found: " + user.getEmail()))
                .orElse(ResponseEntity.status(404).body("User not found"));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/revoke-refresh")
    public ResponseEntity<?> revokeRefresh(@RequestBody RefreshRequestDTO body) {
        refreshTokenService.revokeToken(body.refreshToken());
        return ResponseEntity.ok("Refresh token revoked.");
    }
}