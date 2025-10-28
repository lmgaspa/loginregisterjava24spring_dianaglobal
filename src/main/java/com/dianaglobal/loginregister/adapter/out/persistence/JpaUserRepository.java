package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.SpringUserRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.UserEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class JpaUserRepository implements UserRepositoryPort {

    private final SpringUserRepository repository;

    @Override
    public void save(User user) {
        repository.save(UserEntity.fromDomain(user));
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return repository.findByEmail(email).map(UserEntity::toDomain);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return repository.findById(id).map(UserEntity::toDomain);
    }

    @Override
    public void updatePassword(UUID userId, String encodedPassword) {
        var ent = repository.findById(userId).orElseThrow();
        ent.setPassword(encodedPassword);
        repository.save(ent);
    }

    @Override
    public void markEmailConfirmed(UUID userId) {
        var ent = repository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));
        if (!ent.isEmailConfirmed()) {
            ent.setEmailConfirmed(true);
            repository.save(ent);
        }
    }
}
