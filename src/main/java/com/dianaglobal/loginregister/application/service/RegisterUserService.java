// src/main/java/com/dianaglobal/loginregister/application/service/RegisterUserService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegisterUserService implements RegisterUserUseCase {

    private final UserRepositoryPort userRepository;
    private final PasswordEncoder encoder;

    @Override
    public void register(String name, String email, String password) {
        validatePasswordStrength(password);

        final String normalizedEmail = email == null ? null : email.trim().toLowerCase();
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("E-mail is required.");
        }

        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new DuplicateKeyException("E-mail is already registered");
        }

        User user = User.builder()
                .id(UUID.randomUUID())
                .name(name == null ? null : name.trim())
                .email(normalizedEmail)
                .password(encoder.encode(password))
                .emailConfirmed(false)
                .passwordSet(true)     // registro por senha -> já possui senha
                .authProvider(null)    // não é OAuth
                .build();

        userRepository.save(user);
    }

    @Override
    public User registerOauthUser(String name, String email, String googleSub) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("E-mail is required.");
        }
        final String normalizedEmail = email.trim().toLowerCase();

        var existing = userRepository.findByEmail(normalizedEmail);
        if (existing.isPresent()) {
            User u = existing.get();
            // Garante confirmação para contas OAuth
            if (!u.isEmailConfirmed()) {
                u.setEmailConfirmed(true);
            }
            // Marca origin OAuth (idempotente)
            if (u.getAuthProvider() == null) {
                u.setAuthProvider("GOOGLE");
            }
            // Se estiver usando providerId, setar aqui (campo comentado no model)
            // if (u.getProviderId() == null) u.setProviderId(googleSub);

            userRepository.save(u);
            log.info("[OAUTH GOOGLE] Linked existing user {} as GOOGLE {}", normalizedEmail, googleSub);
            return u;
        }

        // Não existe -> cria novo confirmado, sem senha (passwordSet=false)
        String random = UUID.randomUUID().toString();

        User u = User.builder()
                .id(UUID.randomUUID())
                .name(name == null ? null : name.trim())
                .email(normalizedEmail)
                .password(encoder.encode(random)) // placeholder
                .emailConfirmed(true)   // OAuth garante e-mail verificado
                .passwordSet(false)     // ainda não definiu senha para login por senha
                .authProvider("GOOGLE")
                // .providerId(googleSub)
                .build();

        userRepository.save(u);
        log.info("[OAUTH GOOGLE] Created new user {} as GOOGLE {}", normalizedEmail, googleSub);
        return u;
    }

    // --- helpers ---
    private static void validatePasswordStrength(String pwd) {
        if (pwd == null || pwd.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        boolean hasUpper = pwd.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = pwd.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = pwd.chars().anyMatch(Character::isDigit);

        if (!hasUpper) throw new IllegalArgumentException("Password must include at least 1 uppercase letter");
        if (!hasLower) throw new IllegalArgumentException("Password must include at least 1 lowercase letter");
        if (!hasDigit) throw new IllegalArgumentException("Password must include at least 1 digit");
    }
}
