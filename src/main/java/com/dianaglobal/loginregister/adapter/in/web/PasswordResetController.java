// src/main/java/com/dianaglobal/loginregister/adapter/in/web/PasswordResetController.java
package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.password.ForgotPasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.password.ResetPasswordRequest;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.PasswordResetService;
import com.dianaglobal.loginregister.config.ApiPaths;
import com.dianaglobal.loginregister.domain.model.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping(ApiPaths.AUTH_BASE)
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService service;
    private final UserRepositoryPort userRepositoryPort;

    @Value("${application.frontend.base-url}")
    private String frontendBaseUrl;

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgot(@RequestBody @Valid ForgotPasswordRequest body) {
        String normalizedEmail = body.email().trim().toLowerCase();
        Optional<User> userOpt = userRepositoryPort.findByEmail(normalizedEmail);
        
        // Se usuário não existe, retornar 204 (não vazar informação)
        if (userOpt.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        
        User user = userOpt.get();
        
        // Verificar se é Google user sem senha (mesma lógica do /login)
        if ("GOOGLE".equalsIgnoreCase(user.getAuthProvider()) && !user.isPasswordSet()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "message", "Use Sign in with Google or set a password first.",
                            "error", "PASSWORD_NOT_SET",
                            "auth_provider", "GOOGLE"
                    ));
        }
        
        // Caso contrário, processar normalmente
        service.requestReset(body.email(), frontendBaseUrl);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> reset(@RequestBody @Valid ResetPasswordRequest body) {
        service.resetPassword(body.token(), body.newPassword());
        return ResponseEntity.ok().build();
    }

    public record MessageResponse(String message) {}
}
