// src/main/java/com/dianaglobal/loginregister/application/service/AccountConfirmationService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.AccountConfirmationEmailService;
import com.dianaglobal.loginregister.application.event.UserConfirmedListener;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountConfirmationService {

    private final UserRepositoryPort userRepository;
    private final AccountConfirmationTokenService confirmationTokenService;
    private final AccountConfirmationEmailService emailService;
    private final ConfirmationResendThrottleService throttleService;
    private final UserConfirmedListener userConfirmedListener;

    @Value("${application.confirmation.minutes:45}")
    private int expirationMinutes;

    /** Dispara (se existir usuário) um novo e-mail de confirmação. */
    public void requestConfirmation(String email, String frontendBaseUrl) {
        final String normalized = normalize(email);
        if (normalized == null) return;

        Optional<User> opt = userRepository.findByEmail(normalized);
        if (opt.isEmpty()) {
            log.debug("[CONFIRMATION] request for non-existing email {}", normalized);
            return;
        }

        User user = opt.get();
        String token = confirmationTokenService.issue(user.getId(), expirationMinutes);
        String linkUrl = buildConfirmLink(frontendBaseUrl, token);

        try {
            emailService.send(user.getEmail(), user.getName(), linkUrl, expirationMinutes);
        } catch (Exception e) {
            log.warn("[CONFIRMATION] failed to send email to {}: {}", normalized, e.getMessage());
        }
    }

    /** Variante com nome customizável (opcional). */
    public void requestConfirmation(String email, String name, String frontendBaseUrl, boolean forceName) {
        final String normalized = normalize(email);
        if (normalized == null) return;

        Optional<User> opt = userRepository.findByEmail(normalized);
        if (opt.isEmpty()) {
            log.debug("[CONFIRMATION] request (forceName) for non-existing email {}", normalized);
            return;
        }

        User user = opt.get();
        String token = confirmationTokenService.issue(user.getId(), expirationMinutes);
        String confirmUrl = buildConfirmLink(frontendBaseUrl, token);

        try {
            String safeName = forceName ? (name == null ? "" : name) : user.getName();
            emailService.send(user.getEmail(), safeName, confirmUrl, expirationMinutes);
        } catch (Exception e) {
            log.warn("[CONFIRMATION] failed to send email to {}: {}", normalized, e.getMessage());
        }
    }

    /** Consome o token e confirma o e-mail do usuário. */
    public void confirm(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Invalid confirmation token");
        }

        var payload = confirmationTokenService.consume(token);
        UUID userId = payload.userId();
        userRepository.markEmailConfirmed(userId);
        log.info("[CONFIRMATION] email confirmed for user {}", userId);

        userRepository.findById(userId).ifPresent(user -> {
            try {
                userConfirmedListener.onUserConfirmed(user);
            } catch (Exception e) {
                log.warn("[CONFIRMATION] welcome e-mail failed for {}: {}", user.getEmail(), e.getMessage());
            }
        });
    }

    /* ======================== Reenvio com cooldown ======================== */
    public record ResendResult(HttpStatus httpStatus, Object body) {}

    public ResendResult resendWithThrottle(String email, String frontendBaseUrl, Instant now) {
        String norm = normalize(email);
        if (norm == null) {
            return new ResendResult(HttpStatus.BAD_REQUEST, Map.of(
                    "error", "INVALID_EMAIL",
                    "message", "Email is required"
            ));
        }

        var userOpt = userRepository.findByEmail(norm);
        if (userOpt.isEmpty()) {
            // Resposta idêntica por segurança (não revelar existência)
            return new ResendResult(HttpStatus.OK, Map.of(
                    "status", "CONFIRMATION_EMAIL_SENT",
                    "canResend", false,
                    "cooldownSecondsRemaining", 0,
                    "attemptsToday", 0,
                    "maxPerDay", 5
            ));
        }

        var user = userOpt.get();
        if (user.isEmailConfirmed()) {
            return new ResendResult(HttpStatus.OK, Map.of(
                    "status", "ALREADY_CONFIRMED",
                    "canResend", false,
                    "cooldownSecondsRemaining", 0,
                    "attemptsToday", 0,
                    "maxPerDay", 5
            ));
        }

        var info = throttleService.preview(user.getId(), now);
        if (!info.canResend()) {
            return new ResendResult(HttpStatus.TOO_MANY_REQUESTS, Map.of(
                    "error", "TOO_MANY_REQUESTS",
                    "message", "Please wait before requesting another confirmation e-mail.",
                    "canResend", false,
                    "cooldownSecondsRemaining", info.cooldownSecondsRemaining(),
                    "attemptsToday", info.attemptsToday(),
                    "maxPerDay", info.maxPerDay(),
                    "nextAllowedAt", info.nextAllowedAt()
            ));
        }

        // invalida tokens antigos e emite um novo
        confirmationTokenService.invalidateAllFor(user.getId());
        String rawToken = confirmationTokenService.issue(user.getId(), expirationMinutes);
        String linkUrl = buildConfirmLink(frontendBaseUrl, rawToken);

        try {
            emailService.send(user.getEmail(), user.getName(), linkUrl, expirationMinutes);
        } catch (Exception e) {
            log.warn("[CONFIRMATION] failed to resend email to {}: {}", user.getEmail(), e.getMessage());
        }

        var after = throttleService.registerSend(user.getId(), now, null);

        return new ResendResult(HttpStatus.OK, Map.of(
                "status", "CONFIRMATION_EMAIL_SENT",
                "canResend", after.canResend(),
                "cooldownSecondsRemaining", after.cooldownSecondsRemaining(),
                "attemptsToday", after.attemptsToday(),
                "maxPerDay", after.maxPerDay(),
                "nextAllowedAt", after.nextAllowedAt()
        ));
    }

    /* ======================== utils ======================== */
    private static String normalize(String email) {
        if (email == null) return null;
        String e = email.trim().toLowerCase();
        return e.isBlank() ? null : e;
    }

    private static String buildConfirmLink(String frontendBaseUrl, String token) {
        String base = (frontendBaseUrl == null || frontendBaseUrl.isBlank())
                ? "https://www.dianaglobal.com.br"
                : frontendBaseUrl.trim();
        String path = "confirm-account?token=" + urlEncode(token);
        return base.endsWith("/") ? base + path : base + "/" + path;
    }

    private static String urlEncode(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
