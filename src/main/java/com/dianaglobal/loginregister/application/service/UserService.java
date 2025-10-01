// src/main/java/com/dianaglobal/loginregister/application/service/UserService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepositoryPort userRepository;

    /** Busca por e-mail normalizando (trim/lowercase). */
    public Optional<User> findByEmail(String email) {
        if (email == null) return Optional.empty();
        String normalized = email.trim().toLowerCase();
        return userRepository.findByEmail(normalized);
    }

    /** Persiste a entidade e retorna o próprio usuário. */
    public User save(User user) {
        userRepository.save(user);
        return user;
    }

    /** Busca por e-mail ou lança IllegalArgumentException. */
    public User getByEmailOrThrow(String email) {
        return findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    /** Marca o e-mail como confirmado. */
    public void markEmailConfirmed(UUID userId) {
        User u = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!u.isEmailConfirmed()) {
            u.setEmailConfirmed(true);
            userRepository.save(u);
        }
    }
}
