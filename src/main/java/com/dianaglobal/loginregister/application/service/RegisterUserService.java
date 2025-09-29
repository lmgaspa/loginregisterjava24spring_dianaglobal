// src/main/java/com/dianaglobal/loginregister/application/service/RegisterUserService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RegisterUserService implements RegisterUserUseCase {

    private final UserRepositoryPort userRepository;
    private final PasswordEncoder encoder;

    @Override
    public void register(String name, String email, String password) {
        validatePasswordStrength(password); // <— strong rule

        final String normalizedEmail = email == null ? null : email.trim().toLowerCase();
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("E-mail is required.");
        }
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new RuntimeException("Email already in use");
        }

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setName(name == null ? null : name.trim());
        user.setEmail(normalizedEmail);
        user.setPassword(encoder.encode(password));
        userRepository.save(user);
    }

    // --- helpers ---
    private static void validatePasswordStrength(String pwd) {
        if (pwd == null || pwd.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        boolean hasUpper = pwd.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = pwd.chars().anyMatch(Character::isLowerCase);
        long digits = pwd.chars().filter(Character::isDigit).count();

        if (!hasUpper) throw new IllegalArgumentException("Password must contain at least 1 uppercase letter");
        if (!hasLower) throw new IllegalArgumentException("Password must contain at least 1 lowercase letter");
        if (digits < 6) throw new IllegalArgumentException("Password must contain at least 6 digits");
    }
}
