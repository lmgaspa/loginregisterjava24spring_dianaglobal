package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.EmailChangeService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class EmailChangeController {

    private final UserRepositoryPort userRepositoryPort;
    private final EmailChangeService emailChangeService;

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    public record MessageResponse(String message) {}

    public record ChangeEmailRequest(
            @Email(message="Invalid e-mail")
            @Pattern(regexp="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    message="E-mail must contain a valid domain")
            String newEmail
    ) {}

    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/email/change-request", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> requestEmailChange(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid ChangeEmailRequest req) {

        var user = userRepositoryPort.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        emailChangeService.requestChange(user.getId(), req.newEmail().trim().toLowerCase(), frontendBaseUrl);
        return ResponseEntity.ok(new MessageResponse("We sent a confirmation link to your new e-mail."));
    }

    @RequestMapping(
            value = "/email/change-confirm",
            method = { RequestMethod.GET, RequestMethod.POST },
            produces = "application/json"
    )
    public ResponseEntity<MessageResponse> confirmEmailChange(@RequestParam("token") String token) {
        emailChangeService.confirm(token);
        return ResponseEntity.ok(new MessageResponse("E-mail changed successfully"));
    }
}

