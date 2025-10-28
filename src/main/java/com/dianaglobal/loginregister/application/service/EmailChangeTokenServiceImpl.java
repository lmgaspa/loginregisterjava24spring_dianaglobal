// src/main/java/com/dianaglobal/loginregister/application/service/EmailChangeTokenServiceImpl.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.persistence.EmailChangeTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.EmailChangeTokenEntity;
import com.dianaglobal.loginregister.application.service.exception.TokenAlreadyUsedException;
import com.dianaglobal.loginregister.application.service.exception.TokenExpiredException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailChangeTokenServiceImpl implements EmailChangeTokenService {

    private final EmailChangeTokenRepository repo;

    private static String sha256Base64Url(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String newRawToken() {
        return UUID.randomUUID() + "." + UUID.randomUUID();
    }

    @Override
    public void invalidateAllFor(UUID userId) {
        List<EmailChangeTokenEntity> tokens = repo.findAllByUserIdAndValidTrue(userId);
        for (EmailChangeTokenEntity t : tokens) {
            t.setValid(false);
            repo.save(t);
        }
    }

    @Override
    public String issue(UUID userId, String newEmailNormalized, Duration ttl) {
        if (userId == null) throw new IllegalArgumentException("userId is required");
        if (newEmailNormalized == null || newEmailNormalized.isBlank()) {
            throw new IllegalArgumentException("newEmailNormalized is required");
        }
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl must be > 0");
        }

        String raw = newRawToken();
        String hash = sha256Base64Url(raw);

        Instant now = Instant.now();
        EmailChangeTokenEntity entity = EmailChangeTokenEntity.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .tokenHash(hash)
                .newEmailNormalized(newEmailNormalized)
                .createdAt(now)
                .expiresAt(now.plus(ttl))
                .valid(true)
                .build();

        repo.save(entity);
        return raw;
    }

    @Override
    public Payload consume(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("Invalid token");
        }
        String hash = sha256Base64Url(rawToken);

        EmailChangeTokenEntity t = repo.findByTokenHash(hash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid token"));

        Instant now = Instant.now();

        if (t.getExpiresAt() != null && now.isAfter(t.getExpiresAt())) {
            throw new TokenExpiredException("Token expired");
        }
        if (!t.isValid() || t.getConsumedAt() != null) {
            throw new TokenAlreadyUsedException("Token already used");
        }

        t.setConsumedAt(now);
        t.setValid(false);
        repo.save(t);

        return new Payload(t.getUserId(), t.getNewEmailNormalized());
    }
}
