package com.dianaglobal.loginregister.application.port.out;

import com.dianaglobal.loginregister.domain.model.User;

import java.util.Optional;

public interface UserRepositoryPort {
    void save(User user);
    Optional<User> findByEmail(String email);
}

