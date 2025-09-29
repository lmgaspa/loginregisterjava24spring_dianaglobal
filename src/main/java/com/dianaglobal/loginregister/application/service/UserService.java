// src/main/java/com/dianaglobal/loginregister/application/service/UserService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepositoryPort userRepositoryPort;

    public Optional<User> findByEmail(String email) {
        String normalized = email == null ? null : email.trim().toLowerCase();
        return userRepositoryPort.findByEmail(normalized);
    }
}
