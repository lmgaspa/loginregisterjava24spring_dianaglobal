package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.email.ChangeEmailRequest;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.EmailChangeService;
import com.dianaglobal.loginregister.config.ApiPaths;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.AUTH_EMAIL)
@RequiredArgsConstructor
@Validated
public class EmailChangeController {

    private final UserRepositoryPort userRepositoryPort;
    private final EmailChangeService emailChangeService;

    @Value("${application.frontend.base-url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    public record MessageResponse(String message) {}

    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = "/change-request", consumes = "application/json", produces = "application/json")
    public ResponseEntity<MessageResponse> requestEmailChange(
            @AuthenticationPrincipal UserDetails principal,
            @RequestBody @Valid ChangeEmailRequest req
    ) {
        var user = userRepositoryPort.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        emailChangeService.requestChange(
                user.getId(),
                req.newEmail().trim().toLowerCase(),
                frontendBaseUrl
        );
        return ResponseEntity.ok(new MessageResponse("We sent a confirmation link to your new e-mail."));
    }

    @RequestMapping(
            value = "/change-confirm",
            method = { RequestMethod.GET, RequestMethod.POST },
            produces = "application/json"
    )
    public ResponseEntity<MessageResponse> confirmEmailChange(
            @RequestParam("token") String token
    ) {
        emailChangeService.confirm(token);
        return ResponseEntity.ok(new MessageResponse("E-mail changed successfully"));
    }
}
