package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
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
        validatePasswordStrength(password);

        final String normalizedEmail = email == null ? null : email.trim().toLowerCase();
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("E-mail is required.");
        }

        // Se já existir, lançamos DuplicateKeyException -> 409 via GlobalExceptionHandler
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new DuplicateKeyException("E-mail is already registered");
        }

        User user = User.builder()
                .id(UUID.randomUUID())
                .name(name == null ? null : name.trim())
                .email(normalizedEmail)
                .password(encoder.encode(password))
                .emailConfirmed(false)
                .build();

        userRepository.save(user);
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
