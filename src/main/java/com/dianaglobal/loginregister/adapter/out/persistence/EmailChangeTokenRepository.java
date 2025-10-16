package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.EmailChangeTokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailChangeTokenRepository extends MongoRepository<EmailChangeTokenEntity, UUID> {
    List<EmailChangeTokenEntity> findAllByUserIdAndValidTrue(UUID userId);
    Optional<EmailChangeTokenEntity> findByTokenHash(String tokenHash);
}
