package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.password.ChangePasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.password.SetPasswordUnauthenticatedRequest;
import com.dianaglobal.loginregister.adapter.out.mail.PasswordSetEmailService;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.config.ApiPaths;
import com.dianaglobal.loginregister.domain.model.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping(    ApiPaths.AUTH_PASSWORD)
@RequiredArgsConstructor
@Validated
public class PasswordController {

    private final UserRepositoryPort userRepositoryPort;
    private final PasswordEncoder passwordEncoder;
    private final PasswordSetEmailService passwordSetEmailService;

    // CHANGE PASSWORD (usuário autenticado)
    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/change", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> changePassword(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid ChangePasswordRequest body
    ) {
        var user = userRepositoryPort.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordEncoder.matches(body.currentPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Current password is incorrect"));
        }

        user.setPassword(passwordEncoder.encode(body.newPassword()));
        user.setPasswordSet(true);
        userRepositoryPort.save(user);

        try {
            passwordSetEmailService.sendChange(user.getEmail(), user.getName());
        } catch (Exception ignored) {}

        return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
    }

    // SET PASSWORD UNAUTHENTICATED (google users sem senha)
    @PostMapping(value = "/set-unauthenticated", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> setPasswordUnauthenticated(
            @RequestBody @Valid SetPasswordUnauthenticatedRequest request
    ) {
        String requestId = UUID.randomUUID().toString();
        log.info("[PASSWORD SET UNAUTH REQUEST {}] Attempt to set password for email: {}",
                requestId, request.email());

        try {
            var userOpt = userRepositoryPort.findByEmail(request.email().trim().toLowerCase());
            if (userOpt.isEmpty()) {
                log.warn("[PASSWORD SET UNAUTH ERROR {}] User not found: {}", requestId, request.email());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found"));
            }

            User user = userOpt.get();

            if (!"GOOGLE".equalsIgnoreCase(user.getAuthProvider())) {
                log.warn("[PASSWORD SET UNAUTH ERROR {}] User is not Google Auth: {}", requestId, user.getEmail());
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new MessageResponse("This endpoint is only for Google Auth users"));
            }

            if (user.isPasswordSet()) {
                log.warn("[PASSWORD SET UNAUTH ERROR {}] User already has password set: {}", requestId, user.getEmail());
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new MessageResponse("User already has password set"));
            }

            String hashedPassword = passwordEncoder.encode(request.newPassword());
            user.setPassword(hashedPassword);
            user.setPasswordSet(true);
            userRepositoryPort.save(user);

            log.info("[PASSWORD SET UNAUTH SUCCESS {}] Password set for Google Auth user: {}",
                    requestId, user.getEmail());

            try {
                passwordSetEmailService.sendFirstDefinitionForGoogle(user.getEmail(), user.getName());
            } catch (Exception ex) {
                log.warn("[PASSWORD SET UNAUTH EMAIL WARN {}] Failed to send notification: {}",
                        requestId, ex.getMessage());
            }

            return ResponseEntity.ok(new MessageResponse("Password set successfully"));

        } catch (Exception e) {
            log.error("[PASSWORD SET UNAUTH ERROR {}] Unexpected error: {}", requestId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal server error"));
        }
    }

    public record MessageResponse(String message) {}
}
