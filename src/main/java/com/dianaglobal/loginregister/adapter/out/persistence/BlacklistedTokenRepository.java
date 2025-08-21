package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.domain.model.BlacklistedToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface BlacklistedTokenRepository extends MongoRepository<BlacklistedToken, String> {
    Optional<BlacklistedToken> findByToken(String token);
}
