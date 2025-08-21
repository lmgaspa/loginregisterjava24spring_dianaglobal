package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.ForgotPasswordRequest;
import com.dianaglobal.loginregister.adapter.in.dto.ResetPasswordRequest;
import com.dianaglobal.loginregister.application.service.PasswordResetService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService service;

    @Value("${application.frontend.base-url}")
    private String frontendBaseUrl;

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgot(@RequestBody ForgotPasswordRequest body) {
        service.requestReset(body.email(), frontendBaseUrl);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> reset(@RequestBody ResetPasswordRequest body) {
        service.resetPassword(body.token(), body.newPassword());
        return ResponseEntity.ok().build();
    }
}
