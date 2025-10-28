package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.password.ChangePasswordRequest;
import com.dianaglobal.loginregister.adapter.out.mail.PasswordSetEmailService;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class PasswordManagementController {

    private final UserRepositoryPort userRepositoryPort;
    private final PasswordEncoder passwordEncoder;
    
    @Qualifier("passwordSetEmailService")
    private final PasswordSetEmailService passwordSetEmailService;

    public record MessageResponse(String message) {}

    // ===================== SET PASSWORD UNAUTHENTICATED (Google Auth Users) =====================
    public record SetPasswordUnauthenticatedRequest(
            @NotBlank(message = "Email is required")
            @Email(message = "Invalid email format")
            String email,
            
            @NotBlank(message = "Password cannot be blank")
            @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
            @Pattern(
                    regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).{8,}$",
                    message = "Password must include at least 1 uppercase letter, 1 lowercase letter, and 1 digit and be at least 8 characters"
            )
            String newPassword
    ) {}

    @PostMapping(value = "/password/set-unauthenticated", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> setPasswordUnauthenticated(
            @RequestBody @Valid SetPasswordUnauthenticatedRequest request
    ) {
        String requestId = java.util.UUID.randomUUID().toString();
        log.info("[PASSWORD SET UNAUTH REQUEST {}] Attempt to set password for email: {}", 
                requestId, request.email());
        
        try {
            // Find user by email
            var userOpt = userRepositoryPort.findByEmail(request.email().trim().toLowerCase());
            if (userOpt.isEmpty()) {
                log.warn("[PASSWORD SET UNAUTH ERROR {}] User not found: {}", requestId, request.email());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new MessageResponse("User not found"));
            }
            
            User user = userOpt.get();
            
            // Validate user is Google Auth and doesn't have password set
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
            
            // Set new password
            String hashedPassword = passwordEncoder.encode(request.newPassword());
            user.setPassword(hashedPassword);
            user.setPasswordSet(true);
            userRepositoryPort.save(user);
            
            log.info("[PASSWORD SET UNAUTH SUCCESS {}] Password set for Google Auth user: {}", 
                    requestId, user.getEmail());
            
            // Send notification email
            try {
                passwordSetEmailService.sendFirstDefinitionForGoogle(user.getEmail(), user.getName());
            } catch (Exception ex) {
                log.warn("[PASSWORD SET UNAUTH EMAIL WARN {}] Failed to send notification: {}", requestId, ex.getMessage());
            }
            
            return ResponseEntity.ok(new MessageResponse("Password set successfully"));
            
        } catch (Exception e) {
            log.error("[PASSWORD SET UNAUTH ERROR {}] Unexpected error: {}", requestId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal server error"));
        }
    }

    // ===================== PASSWORD CHANGE (autenticado) =====================
    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/password/change", consumes = "application/json", produces = "application/json")
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

        try { 
            passwordSetEmailService.sendChange(user.getEmail(), user.getName()); 
        } catch (Exception ignored) {}

        return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
    }
}

