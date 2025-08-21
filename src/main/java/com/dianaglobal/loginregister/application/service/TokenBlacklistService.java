package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.persistence.BlacklistedTokenRepository;
import com.dianaglobal.loginregister.domain.model.BlacklistedToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final BlacklistedTokenRepository repository;

    public void blacklist(String token, Instant expiration) {
        BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                .token(token)
                .expiration(expiration)
                .build();
        repository.save(blacklistedToken);
    }

    public boolean isBlacklisted(String token) {
        return repository.findByToken(token).isPresent();
    }
}
