// src/main/java/com/dianaglobal/loginregister/application/service/PasswordResetService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.PasswordResetEmailService;
import com.dianaglobal.loginregister.adapter.out.persistence.PasswordResetTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.PasswordResetTokenEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
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
public class PasswordResetService {

    private final UserRepositoryPort userRepo;
    private final PasswordResetTokenRepository tokenRepo;
    private final PasswordResetEmailService emailService;
    private final PasswordEncoder passwordEncoder;

    /** Issues a reset link by creating a random token, storing only its SHA-256 hash, and e-mailing the link. */
    public void requestReset(String email, String frontendBaseUrl) {
        Optional<com.dianaglobal.loginregister.domain.model.User> opt =
                userRepo.findByEmail(email == null ? "" : email.trim().toLowerCase());
        if (opt.isEmpty()) return; // do not leak existence

        var user = opt.get();

        // Enforce single active token per user
        tokenRepo.deleteByUserId(user.getId());

        // 32 random bytes -> URL-safe token
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String tokenPlain = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String tokenHash  = sha256Url(raw);

        Instant expires = Instant.now().plusSeconds(45 * 60);

        var entity = PasswordResetTokenEntity.builder()
                .id(UUID.randomUUID())
                .userId(user.getId())
                .tokenHash(tokenHash)
                .createdAt(new Date())
                .expiresAt(Date.from(expires))
                .build();

        tokenRepo.save(entity);

        String link = frontendBaseUrl + "/reset-password?token=" + tokenPlain;
        emailService.sendPasswordReset(user.getEmail(), user.getName(), link, 45);
    }

    /** Validates token and actually updates the password in Mongo (BCrypt). Token becomes single-use. */
    @Transactional
    public void resetPassword(String tokenPlain, String newPassword) {
        validatePasswordStrength(newPassword);

        byte[] raw = Base64.getUrlDecoder().decode(tokenPlain);
        String tokenHash = sha256Url(raw);

        var entity = tokenRepo.findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(tokenHash, new Date())
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired token"));

        userRepo.updatePassword(entity.getUserId(), passwordEncoder.encode(newPassword));

        entity.setUsedAt(new Date());
        tokenRepo.save(entity);
        // Alternatively: tokenRepo.deleteById(entity.getId());
    }

    // --- helpers ---

    private static void validatePasswordStrength(String pwd) {
        if (pwd == null || pwd.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        boolean hasUpper = pwd.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = pwd.chars().anyMatch(Character::isLowerCase);
        long digits      = pwd.chars().filter(Character::isDigit).count();

        if (!hasUpper) throw new IllegalArgumentException("Password must contain at least 1 uppercase letter");
        if (!hasLower) throw new IllegalArgumentException("Password must contain at least 1 lowercase letter");
        if (digits < 6) throw new IllegalArgumentException("Password must contain at least 6 digits");
    }

    private static String sha256Url(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
