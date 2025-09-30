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

import java.lang.reflect.Method;
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
                .build();

        userRepository.save(user);
    }

    @Override
    public void registerOauthUser(String name, String email, String googleSub) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("E-mail is required for OAuth user");
        }
        final String normalizedEmail = email.trim().toLowerCase();

        var existing = userRepository.findByEmail(normalizedEmail);
        if (existing.isPresent()) {
            User u = existing.get();

            // Confirma o e-mail (OAuth já validou)
            if (!u.isEmailConfirmed()) {
                u.setEmailConfirmed(true);
            }

            // Tenta setar provider/providerId via reflexão (se a sua entidade tiver)
            tryInvokeSetter(u, "setAuthProvider", String.class, "GOOGLE");
            tryInvokeSetter(u, "setProviderId", String.class, googleSub);

            userRepository.save(u);
            log.info("[OAUTH GOOGLE] Linked existing user {} as GOOGLE {}", normalizedEmail, googleSub);
            return;
        }

        // Não existia → cria novo usuário já confirmado
        String randomPassword = UUID.randomUUID().toString();

        User u = new User();
        u.setId(UUID.randomUUID());
        u.setName(name == null ? null : name.trim());
        u.setEmail(normalizedEmail);
        u.setPassword(encoder.encode(randomPassword));
        u.setEmailConfirmed(true); // OAuth → confirmado

        // Tenta setar provider/providerId via reflexão (se a sua entidade tiver)
        tryInvokeSetter(u, "setAuthProvider", String.class, "GOOGLE");
        tryInvokeSetter(u, "setProviderId", String.class, googleSub);

        userRepository.save(u);
        log.info("[OAUTH GOOGLE] Created new user {} as GOOGLE {}", normalizedEmail, googleSub);
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

    /**
     * Invoca um setter opcional via reflexão. Se o método não existir na entidade,
     * apenas ignora silenciosamente (mantém OCP e compatibilidade).
     */
    private static void tryInvokeSetter(Object target, String methodName, Class<?> paramType, Object arg) {
        try {
            Method m = target.getClass().getMethod(methodName, paramType);
            m.invoke(target, arg);
        } catch (NoSuchMethodException nsme) {
            // Campo não existe na sua entidade -> ignorar
        } catch (Exception e) {
            // Qualquer outra falha de reflexão -> loga e segue
            try {
                log.debug("Optional setter {} not applied: {}", methodName, e.getMessage());
            } catch (Exception ignore) { /* logger pode não estar pronto em testes */ }
        }
    }
}
