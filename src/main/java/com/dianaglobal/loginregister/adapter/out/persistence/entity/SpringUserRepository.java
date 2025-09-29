// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/SpringUserRepository.java
package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.UserEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
import java.util.UUID;

public interface SpringUserRepository extends MongoRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmail(String email);
}
