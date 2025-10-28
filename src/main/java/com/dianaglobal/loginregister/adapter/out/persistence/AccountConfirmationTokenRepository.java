package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AccountConfirmationTokenRepository extends MongoRepository<AccountConfirmationTokenEntity, UUID> {

    /** Busca pelo hash do token; regras de expiração/uso único são tratadas no service. */
    Optional<AccountConfirmationTokenEntity> findByTokenHash(String tokenHash);

    /** Lista tokens ainda válidos de um usuário (para revogar em massa antes de emitir novo). */
    List<AccountConfirmationTokenEntity> findAllByUserIdAndValidTrue(UUID userId);

    /** Se você quiser realmente apagar tokens antigos de um usuário. (Opcional/unused) */
    void deleteByUserId(UUID userId);
}
