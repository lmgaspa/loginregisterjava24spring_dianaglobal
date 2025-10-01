// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/AccountConfirmationTokenServiceImpl.java
package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import com.dianaglobal.loginregister.application.service.AccountConfirmationTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountConfirmationTokenServiceImpl implements AccountConfirmationTokenService {

    private final AccountConfirmationTokenRepository repo;
    private static final SecureRandom RNG = new SecureRandom();

    @Override
    public String issue(UUID userId, int minutes) {
        if (userId == null) throw new IllegalArgumentException("userId is required");
        if (minutes <= 0) throw new IllegalArgumentException("minutes must be > 0");

        // Opcional: revoga tokens antigos desse usuário para evitar múltiplos links válidos
        try {
            repo.deleteByUserId(userId);
        } catch (Exception e) {
            log.warn("[CONFIRM] failed to delete previous tokens for user {}: {}", userId, e.getMessage());
        }

        final String rawToken = randomToken(); // retorna string URL-safe
        final String tokenHash = sha256Hex(rawToken);

        Instant now = Instant.now();
        Instant exp = now.plus(minutes, ChronoUnit.MINUTES);

        AccountConfirmationTokenEntity entity = AccountConfirmationTokenEntity.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .tokenHash(tokenHash)
                .createdAt(Date.from(now))
                .expiresAt(Date.from(exp))
                .usedAt(null)
                .build();

        repo.save(entity);
        return rawToken; // devolvemos o token "limpo" para ser enviado por e-mail
    }

    @Override
    public ConfirmationPayload consume(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Invalid confirmation token");
        }

        String hash = sha256Hex(token);
        Date now = new Date();

        Optional<AccountConfirmationTokenEntity> opt =
                repo.findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(hash, now);

        AccountConfirmationTokenEntity entity = opt.orElseThrow(
                () -> new IllegalArgumentException("Invalid or expired confirmation link")
        );

        // marca como usado e persiste
        entity.setUsedAt(now);
        repo.save(entity);

        return new ConfirmationPayload(entity.getUserId());
    }

    // ================= helpers =================

    private static String randomToken() {
        byte[] buf = new byte[32]; // 256 bits
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) {
                sb.append(Character.forDigit((b >>> 4) & 0xF, 16))
                        .append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
