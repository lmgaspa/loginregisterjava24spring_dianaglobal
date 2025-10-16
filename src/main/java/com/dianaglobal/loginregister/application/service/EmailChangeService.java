// src/main/java/com/dianaglobal/loginregister/application/service/EmailChangeService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.EmailChangeEmailService;
import com.dianaglobal.loginregister.adapter.out.persistence.EmailChangeTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.EmailChangeTokenEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailChangeService {

    private final UserRepositoryPort userRepository;
    private final EmailChangeTokenRepository tokenRepo;
    private final EmailChangeEmailService emailService;
    private final RefreshTokenService refreshTokenService; // (se não existir, remova esta linha e o uso mais abaixo)

    @Value("${application.email-change.minutes:30}")
    private int ttlMinutes;

    private static String sha256Base64(String raw) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(md.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public void requestChange(UUID userId, String newEmailNormalized, String frontendBaseUrl) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // invalida tokens antigos pendentes
        tokenRepo.findAllByUserIdAndValidTrue(userId).forEach(t -> {
            t.setValid(false);
            tokenRepo.save(t);
        });

        // token bruto + hash
        String rawToken = UUID.randomUUID() + "." + UUID.randomUUID();
        String hash = sha256Base64(rawToken);

        Instant now = Instant.now();
        EmailChangeTokenEntity entity = EmailChangeTokenEntity.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .tokenHash(hash)
                .newEmailNormalized(newEmailNormalized)
                .createdAt(now)
                .expiresAt(now.plus(Duration.ofMinutes(ttlMinutes)))
                .valid(true)
                .build();
        tokenRepo.save(entity);

        // link para o NOVO e-mail
        String link = buildConfirmLink(frontendBaseUrl, rawToken);

        emailService.sendConfirmNew(newEmailNormalized, user.getName(), link, ttlMinutes);

        // opcional: alerta para o antigo
        try {
            if (user.getEmail() != null && !user.getEmail().isBlank()) {
                emailService.sendAlertOld(user.getEmail(), user.getName(), frontendBaseUrl + "/support");
            }
        } catch (Exception ex) {
            log.warn("[EMAIL-CHANGE] alert-old send warn: {}", ex.getMessage());
        }
    }

    public void confirm(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("Invalid token");
        }
        String hash = sha256Base64(rawToken);

        EmailChangeTokenEntity t = tokenRepo.findByTokenHash(hash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid token"));

        Instant now = Instant.now();
        if (!t.isValid() || t.getConsumedAt() != null) {
            throw new IllegalArgumentException("Token already used or invalid");
        }
        if (t.getExpiresAt() != null && now.isAfter(t.getExpiresAt())) {
            throw new IllegalArgumentException("Token expired");
        }

        UUID userId = t.getUserId();
        String newEmail = t.getNewEmailNormalized();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String oldEmail = user.getEmail();
        user.setEmail(newEmail);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        t.setConsumedAt(now);
        t.setValid(false);
        tokenRepo.save(t);
        tokenRepo.findAllByUserIdAndValidTrue(userId).forEach(other -> {
            other.setValid(false);
            tokenRepo.save(other);
        });

        // Se você tiver mesmo um método para revogar todas as sessões do e-mail antigo, use aqui.
        // Exemplo (AJUSTE ao seu RefreshTokenService real):
        // try { if (oldEmail != null) refreshTokenService.revokeAllFor(oldEmail); } catch (Exception ignore) {}

        try {
            emailService.sendChanged(newEmail, user.getName());
        } catch (Exception ex) {
            log.warn("[EMAIL-CHANGE] changed-mail warn: {}", ex.getMessage());
        }

        log.info("[EMAIL-CHANGE] user {} changed e-mail {} -> {}", userId, oldEmail, newEmail);
    }

    private static String buildConfirmLink(String frontendBaseUrl, String token) {
        String base = (frontendBaseUrl == null || frontendBaseUrl.isBlank())
                ? "https://www.dianaglobal.com.br"
                : frontendBaseUrl.trim();
        String path = "email-change/confirm?token=" + token;
        return base.endsWith("/") ? base + path : base + "/" + path;
    }
}
