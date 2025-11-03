package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.ProfileResponseDTO;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.config.ApiPaths;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ApiPaths.AUTH_BASE)
@RequiredArgsConstructor
public class ProfileController {

    private final UserRepositoryPort userRepositoryPort;

    public record MessageResponse(String message) {}

    @GetMapping(value = "/profile", produces = "application/json")
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
}
