package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.AuthResponse;
import com.dianaglobal.loginregister.adapter.in.dto.GenericTokenDTO;
import com.dianaglobal.loginregister.application.service.AccountConfirmationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/confirm")
@RequiredArgsConstructor
@Validated
public class AccountConfirmationController {

    private final AccountConfirmationService service;

    @PostMapping(value = "/request", consumes = "application/json", produces = "application/json")
    public ResponseEntity<AuthResponse> request(
            @RequestBody @Valid ConfirmationRequest body) {
        service.requestConfirmation(body.email(), body.frontendBaseUrl());
        return ResponseEntity.ok(new AuthResponse("If the e-mail exists, a confirmation link has been sent."));
    }

    @PostMapping(value = "/verify", consumes = "application/json", produces = "application/json")
    public ResponseEntity<AuthResponse> verify(@RequestBody @Valid GenericTokenDTO body) {
        service.confirm(body.token());
        return ResponseEntity.ok(new AuthResponse("Account confirmed successfully."));
    }

    // DTOs
    public record ConfirmationRequest(
            @NotBlank
            @Email(message = "Invalid e-mail")
            @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message = "E-mail must contain a valid domain")
            String email,

            @NotBlank String frontendBaseUrl
    ) {}

    @PostMapping(value = "/resend", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> resend(@RequestBody @Valid ConfirmationRequest body) {
        // Anti-enumeração: sempre 200 com shape consistente
        var now = java.time.Instant.now();
            var result = service.resendWithThrottle(body.email(), body.frontendBaseUrl(), now);
        return ResponseEntity.status(result.httpStatus()).body(result.body());
    }
}
