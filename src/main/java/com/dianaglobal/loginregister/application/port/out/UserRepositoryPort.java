package com.dianaglobal.loginregister.application.port.out;

import com.dianaglobal.loginregister.domain.model.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepositoryPort {
    void save(User user);
    void updatePassword(UUID userId, String encodedPassword);
    Optional<User> findById(UUID id);
    Optional<User> findByEmail(String email);
}

