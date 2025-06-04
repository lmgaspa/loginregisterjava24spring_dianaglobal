package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.persistence.RefreshTokenRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.RefreshTokenEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    public RefreshTokenEntity create(String email) {
        RefreshTokenEntity token = RefreshTokenEntity.builder()
                .id(UUID.randomUUID())
                .email(email)
                .token(UUID.randomUUID().toString())
                .expiryDate(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7))
                .revoked(false)
                .build();
        return repository.save(token);
    }

    public boolean validate(String token) {
        return repository.findByToken(token)
                .map(t -> !t.isRevoked() && t.getExpiryDate().after(new Date()))
                .orElse(false);
    }

    public String getEmailByToken(String token) {
        return repository.findByToken(token)
                .map(RefreshTokenEntity::getEmail)
                .orElseThrow(() -> new RuntimeException("Token not found"));
    }

    public void revokeToken(String token) {
        repository.findByToken(token).ifPresent(t -> {
            t.setRevoked(true);
            repository.save(t);
        });
    }
}
