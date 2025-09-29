// src/main/java/com/dianaglobal/loginregister/application/service/AccountConfirmationService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.AccountConfirmationEmailService;
import com.dianaglobal.loginregister.adapter.out.persistence.AccountConfirmationTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AccountConfirmationService {

    private final UserRepositoryPort userRepo;
    private final AccountConfirmationTokenRepository tokenRepo;
    private final AccountConfirmationEmailService emailService;

    private static final int EXP_MINUTES = 45;

    /** Emite um token (45 min), guarda apenas o hash e envia o link por e-mail. */
    public void requestConfirmation(String email, String frontendBaseUrl) {
        final String normalized = email == null ? "" : email.trim().toLowerCase();
        Optional<User> opt = userRepo.findByEmail(normalized);
        if (opt.isEmpty()) return; // não vaza existência

        User user = opt.get();

        // Apenas um token ativo por usuário
        tokenRepo.deleteByUserId(user.getId());

        // Gera token em texto puro (URL-safe) e salva apenas o hash
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String tokenPlain = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String tokenHash  = sha256Url(raw);

        Instant expires = Instant.now().plusSeconds(EXP_MINUTES * 60L);

        AccountConfirmationTokenEntity entity = AccountConfirmationTokenEntity.builder()
                .id(UUID.randomUUID())
                .userId(user.getId())
                .tokenHash(tokenHash)
                .createdAt(new Date())
                .expiresAt(Date.from(expires))
                .build();

        tokenRepo.save(entity);

        String link = frontendBaseUrl + "/confirm-account?token=" + tokenPlain;
        emailService.send(user.getEmail(), user.getName(), link, EXP_MINUTES);
    }

    /** Valida o token e marca o usuário como confirmado; token torna-se single-use. */
    @Transactional
    public void confirm(String tokenPlain) {
        final byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(tokenPlain);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid or expired token");
        }

        String tokenHash = sha256Url(raw);

        var entity = tokenRepo.findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(tokenHash, new Date())
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired token"));

        // Marca o e-mail como confirmado via porta (OCP)
        userRepo.markEmailConfirmed(entity.getUserId());

        entity.setUsedAt(new Date());
        tokenRepo.save(entity);
    }

    private static String sha256Url(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}
