// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/entity/SpringUserRepository.java
package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
import java.util.UUID;

public interface SpringUserRepository extends MongoRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmail(String email);
}
