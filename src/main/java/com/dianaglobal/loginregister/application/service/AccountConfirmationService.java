// src/main/java/com/dianaglobal/loginregister/application/service/AccountConfirmationService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.AccountConfirmationEmailService;
import com.dianaglobal.loginregister.application.event.UserConfirmedListener; // NEW
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountConfirmationService {

    private final UserRepositoryPort userRepository;

    /** Handles token creation and validation for confirmation links. */
    private final AccountConfirmationTokenService confirmationTokenService;

    /** Responsible for sending the confirmation e-mail. */
    private final AccountConfirmationEmailService emailService;

    // torna opcional para não derrubar o app se não houver bean
    @Autowired(required = false)
    private UserConfirmedListener userConfirmedListener;

    /** Confirmation token validity in minutes. */
    @Value("${application.frontend.auth.confirmation-ttl-minutes:60}")
    private int expirationMinutes;

    /** Sends a new confirmation email if user exists. */
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

    /** Overloaded variant allowing custom name usage. */
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

    /** Confirms the token, marks e-mail as confirmed and triggers welcome listener. */
    public void confirm(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Invalid confirmation token");
        }

        AccountConfirmationTokenService.ConfirmationPayload payload =
                confirmationTokenService.consume(token); // throws if invalid/expired/used

        UUID userId = payload.userId();
        userRepository.markEmailConfirmed(userId);
        log.info("[CONFIRMATION] email confirmed for user {}", userId);

        // NEW — Fire event to OCP listener (WelcomeEmailOnConfirm)
        userRepository.findById(userId).ifPresent(user -> {
            try {
                if (userConfirmedListener != null) {
                    userConfirmedListener.onUserConfirmed(user);
                }
            } catch (Exception e) {
                log.warn("[CONFIRMATION] welcome e-mail failed for {}: {}", user.getEmail(), e.getMessage());
            }
        });
    }

    // ===== utils =====

    private static String normalize(String email) {
        if (email == null) return null;
        String e = email.trim().toLowerCase();
        return e.isBlank() ? null : e;
    }

    private static String buildConfirmLink(String frontendBaseUrl, String token) {
        String base = (frontendBaseUrl == null || frontendBaseUrl.isBlank())
                ? "https://www.dianaglobal.com.br"
                : frontendBaseUrl.trim();

        if (base.endsWith("/")) {
            return base + "confirm-account?token=" + urlEncode(token);
        }
        return base + "/confirm-account?token=" + urlEncode(token);
    }

    private static String urlEncode(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
