package com.dianaglobal.loginregister.consent.adapter.in.web;

import com.dianaglobal.loginregister.consent.domain.*;
import com.dianaglobal.loginregister.consent.port.in.LogConsentUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/privacy")
@RequiredArgsConstructor
public class PrivacyController {

    private final LogConsentUseCase logConsent;

    @PostMapping("/consent")
    public ResponseEntity<Void> logConsent(
            @Valid @RequestBody ConsentPayloadDTO body,
            HttpServletRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        String ip = request.getRemoteAddr();
        String ua = request.getHeader("User-Agent");
        if (ua == null) ua = "unknown";

        // Se quiser atrelar ao usuário autenticado, resolva o userId aqui.
        UUID userId = null;

        CookieConsent consent = CookieConsent.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .version(body.getVersion().trim())
                .decision(body.getDecision())
                .categories(new ConsentCategories(
                        body.getCategories() != null && body.getCategories().isAnalytics(),
                        body.getCategories() != null && body.getCategories().isMarketing()
                ))
                .ip(ip)
                .userAgent(ua)
                .createdAt(Instant.now())
                .build();

        logConsent.log(consent);
        return ResponseEntity.noContent().build();
    }
}
