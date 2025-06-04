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
        RefreshTokenEntity token = new RefreshTokenEntity(
                UUID.randomUUID(),
                email,
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7) // 7 dias
        );
        return repository.save(token);
    }

    public boolean validate(String token) {
        return repository.findByToken(token)
                .map(t -> t.getExpiryDate().after(new Date()))
                .orElse(false);
    }

    public String getEmailByToken(String token) {
        return repository.findByToken(token)
                .map(RefreshTokenEntity::getEmail)
                .orElseThrow(() -> new RuntimeException("Token not found"));
    }
}
