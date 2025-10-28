package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.password.RegisterRequest;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.service.AccountConfirmationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class RegistrationController {

    private final RegisterUserUseCase registerService;
    private final AccountConfirmationService accountConfirmationService;

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    public record MessageResponse(String message) {}

    @PostMapping(value = "/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> register(@RequestBody @Valid RegisterRequest request) {
        final String name = request.name() == null ? null : request.name().trim();
        final String email = request.email().trim().toLowerCase();
        final String password = request.password();

        try {
            registerService.register(name, email, password);

            try {
                accountConfirmationService.requestConfirmation(email, frontendBaseUrl);
            } catch (Exception mailEx) {
                log.warn("[REGISTER WARN] failed to send confirmation e-mail: {}", mailEx.getMessage());
            }

            URI location = URI.create("/api/auth/find-user?email=" + email);
            return ResponseEntity.created(location)
                    .header(HttpHeaders.LOCATION, location.toString())
                    .body(new MessageResponse("User successfully registered. Please check your e-mail to confirm your account."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        } catch (DuplicateKeyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new MessageResponse("E-mail is already registered"));
        } catch (Exception e) {
            String id = UUID.randomUUID().toString();
            log.error("[REGISTER ERROR {}] {}", id, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal error. Code: " + id));
        }
    }
}

