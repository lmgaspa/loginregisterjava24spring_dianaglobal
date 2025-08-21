package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.PasswordResetTokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepository extends MongoRepository<PasswordResetTokenEntity, UUID> {
    Optional<PasswordResetTokenEntity> findByTokenHashAndUsedAtIsNullAndExpiresAtAfter(String tokenHash, Date now);
    void deleteByUserId(UUID userId); // para revogar anteriores, se preferir deletar
}