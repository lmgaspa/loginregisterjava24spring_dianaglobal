package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.persistence.AccountConfirmationTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import com.dianaglobal.loginregister.application.service.exception.TokenAlreadyUsedException;
import com.dianaglobal.loginregister.application.service.exception.TokenExpiredException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
public class AccountConfirmationTokenServiceImpl implements AccountConfirmationTokenService {

    private final AccountConfirmationTokenRepository repo;

    public AccountConfirmationTokenServiceImpl(AccountConfirmationTokenRepository repo) {
        this.repo = repo;
    }

    private static String sha256Base64(String raw) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            var digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Override
    public void invalidateAllFor(UUID userId) {
        var tokens = repo.findAllByUserIdAndValidTrue(userId);
        for (var t : tokens) {
            t.setValid(false);
            repo.save(t);
        }
    }

    @Override
    public String issue(UUID userId, int minutes) {
        String rawToken = UUID.randomUUID().toString() + "." + UUID.randomUUID();
        String hash = sha256Base64(rawToken);

        Instant now = Instant.now();
        var entity = new AccountConfirmationTokenEntity();
        entity.setId(UUID.randomUUID());
        entity.setUserId(userId);
        entity.setTokenHash(hash);
        entity.setCreatedAt(now);
        entity.setExpiresAt(now.plusSeconds(minutes * 60L));
        entity.setValid(true);

        repo.save(entity);
        return rawToken;
    }

    @Override
    public ConfirmationPayload consume(String rawToken) {
        String hash = sha256Base64(rawToken);
        var t = repo.findByTokenHash(hash)
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

        return new ConfirmationPayload(t.getUserId());
    }
}
