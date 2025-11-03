// src/main/java/com/dianaglobal/loginregister/adapter/in/web/PasswordResetController.java
package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.password.ForgotPasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.password.ResetPasswordRequest;
import com.dianaglobal.loginregister.application.service.PasswordResetService;
import com.dianaglobal.loginregister.config.ApiPaths;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.AUTH_BASE)
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService service;

    @Value("${application.frontend.base-url}")
    private String frontendBaseUrl;

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgot(@RequestBody @Valid ForgotPasswordRequest body) {
        service.requestReset(body.email(), frontendBaseUrl);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> reset(@RequestBody @Valid ResetPasswordRequest body) {
        service.resetPassword(body.token(), body.newPassword());
        return ResponseEntity.ok().build();
    }
}
