package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.UserEntity;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

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
}

