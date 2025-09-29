package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

public interface AccountConfirmationTokenRepository extends MongoRepository<AccountConfirmationTokenEntity, UUID> {
    Optional<AccountConfirmationTokenEntity> findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(String tokenHash, Date now);
    void deleteByUserId(UUID userId);
}
