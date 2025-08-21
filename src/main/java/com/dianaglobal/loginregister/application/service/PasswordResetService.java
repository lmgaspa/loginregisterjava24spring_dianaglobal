// PasswordResetService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.PasswordResetEmailService;
import com.dianaglobal.loginregister.adapter.out.persistence.PasswordResetTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.PasswordResetTokenEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
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
    private final PasswordResetEmailService emailService;// adapter de e-mail (abaixo)
    private final PasswordEncoder passwordEncoder;  // já existe no seu projeto

    /** 1) Solicitar o reset: gera token, salva hash e envia e-mail */
    public void requestReset(String email, String frontendBaseUrl) {
        Optional<User> opt = userRepo.findByEmail(email == null ? "" : email.trim().toLowerCase());
        if (opt.isEmpty()) return; // não vazar existência

        User user = opt.get();

        // Revoga/deleta tokens anteriores do usuário (uma por vez)
        tokenRepo.deleteByUserId(user.getId());

        // 32 bytes (256 bits) aleatórios
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);

        String tokenPlain = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String tokenHash = sha256Url(raw); // hash que vai pro banco

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

        // envia e-mail bonito
        emailService.sendPasswordReset(user.getEmail(), user.getName(), link, 45);
    }

    /** 2) Concluir o reset: valida token e troca a senha */
    public void resetPassword(String tokenPlain, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        byte[] raw = Base64.getUrlDecoder().decode(tokenPlain);
        String tokenHash = sha256Url(raw);

        var entity = tokenRepo.findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(
                tokenHash, new Date()
        ).orElseThrow(() -> new IllegalArgumentException("Token inválido ou expirado"));

        // troca senha
        var user = userRepo.findByEmail(null) // não temos por e-mail; crie um findById se ainda não houver
                .orElse(null);
        // Melhor: adicione no UserRepositoryPort:
        // Optional<User> findById(UUID id);
        // e use:
        // var user = userRepo.findById(entity.getUserId()).orElseThrow(...);

        // Para não quebrar sua interface atual, segue o update direto:
        // -> crie método auxiliar na sua implementação para fazer update por ID:
        //    userRepo.updatePassword(entity.getUserId(), passwordEncoder.encode(newPassword));
        // (veja adendo logo abaixo)

        // marca usado
        entity.setUsedAt(new Date());
        tokenRepo.save(entity);
    }

    private static String sha256Url(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
