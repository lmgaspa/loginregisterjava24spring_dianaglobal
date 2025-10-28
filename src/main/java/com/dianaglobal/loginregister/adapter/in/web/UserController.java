package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.ProfileResponseDTO;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.UserService;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserRepositoryPort userRepositoryPort;
    private final UserService userService;

    public record MessageResponse(String message) {}

    // ===================== PROFILE =====================
    @GetMapping(value = "/auth/profile", produces = "application/json")
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

    // ===================== FIND USER =====================
    @GetMapping(value = "/auth/find-user", produces = "application/json")
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
}
