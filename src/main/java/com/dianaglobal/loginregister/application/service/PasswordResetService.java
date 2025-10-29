// src/main/java/com/dianaglobal/loginregister/application/service/PasswordResetService.java
package com.dianaglobal.loginregister.application.service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dianaglobal.loginregister.adapter.out.mail.PasswordResetEmailService;
import com.dianaglobal.loginregister.adapter.out.mail.PasswordSetEmailService;
import com.dianaglobal.loginregister.adapter.out.persistence.PasswordResetTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.PasswordResetTokenEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;

import lombok.RequiredArgsConstructor;

@lombok.extern.slf4j.Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepositoryPort userRepo;
    private final PasswordResetTokenRepository tokenRepo;
    private final PasswordResetEmailService emailService;
    private final PasswordSetEmailService passwordSetEmailService;
    private final PasswordEncoder passwordEncoder;

    /** Create a reset link: random token, store only SHA-256 hash, send e-mail. */
    public void requestReset(String email, String frontendBaseUrl) {
        final String normalized = email == null ? "" : email.trim().toLowerCase();
        Optional<User> opt = userRepo.findByEmail(normalized);
        if (opt.isEmpty()) return; // do not leak user existence

        User user = opt.get();

        // Single active token per user
        tokenRepo.deleteByUserId(user.getId());

        // 32 random bytes -> URL-safe plaintext token for the link
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String tokenPlain = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String tokenHash  = sha256Url(raw);

        Instant expires = Instant.now().plusSeconds(45 * 60);

        PasswordResetTokenEntity entity = PasswordResetTokenEntity.builder()
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

    /** Validate token and actually update the password (BCrypt). Token becomes single-use. */
    @Transactional
    public void resetPassword(String tokenPlain, String newPassword) {
        validatePasswordStrength(newPassword);

        final byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(tokenPlain);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid or expired token");
        }

        String tokenHash = sha256Url(raw);

        var entity = tokenRepo.findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(tokenHash, new Date())
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired token"));

        userRepo.updatePassword(entity.getUserId(), passwordEncoder.encode(newPassword));

        entity.setUsedAt(new Date());
        tokenRepo.save(entity);
        
        // Send confirmation email after successful password reset
        try {
            User user = userRepo.findById(entity.getUserId())
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));
            passwordSetEmailService.sendChange(user.getEmail(), user.getName());
        } catch (Exception e) {
            // Log error but don't fail the reset process
            log.warn("Failed to send password reset confirmation email: {}", e.getMessage());
        }
        // Alternatively: tokenRepo.deleteById(entity.getId());
    }

    // --- helpers ---

    // ≥8 chars, ≥1 uppercase, ≥1 lowercase, ≥1 digit
    private static void validatePasswordStrength(String pwd) {
        if (pwd == null || pwd.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        boolean hasUpper = pwd.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = pwd.chars().anyMatch(Character::isLowerCase);
        long digits      = pwd.chars().filter(Character::isDigit).count();

        if (!hasUpper) throw new IllegalArgumentException("Password must contain at least 1 uppercase letter");
        if (!hasLower) throw new IllegalArgumentException("Password must contain at least 1 lowercase letter");
        if (digits < 1) throw new IllegalArgumentException("Password must contain at least 1 digit");
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
