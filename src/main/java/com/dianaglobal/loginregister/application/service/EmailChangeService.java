package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.EmailChangeEmailService;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailChangeService {

    private final UserRepositoryPort userRepository;
    private final EmailChangeTokenService emailChangeTokenService;
    private final EmailChangeEmailService mailer;

    /** Token validity (minutes) for e-mail change confirmation. */
    @Value("${application.emailchange.minutes:45}")
    private int expirationMinutes;

    /** Step 1: user requests to change e-mail -> send confirmation link to NEW e-mail. */
    public void requestChange(UUID userId, String newEmailNormalized, String frontendBaseUrl) {
        if (userId == null) throw new IllegalArgumentException("userId is required");
        String newEmail = normalize(newEmailNormalized);
        if (newEmail == null) throw new IllegalArgumentException("Invalid e-mail");

        // ensure user exists
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // deny if newEmail already in use
        Optional<User> existing = userRepository.findByEmail(newEmail);
        if (existing.isPresent() && !existing.get().getId().equals(userId)) {
            throw new IllegalArgumentException("E-mail is already registered");
        }

        // single-use: invalidate previous tokens then issue a new one
        emailChangeTokenService.invalidateAllFor(userId);
        String raw = emailChangeTokenService.issue(
                userId, newEmail, Duration.ofMinutes(expirationMinutes));

        String link = buildConfirmLink(frontendBaseUrl, raw);
        // send to NEW email
        mailer.sendConfirmNew(newEmail, user.getName(), link, expirationMinutes);

        // optional: alert OLD email
        try {
            mailer.sendAlertOld(user.getEmail(), user.getName(), frontendBaseUrl + "/support");
        } catch (Exception ignore) {
            log.debug("[EMAIL CHANGE] alert to old e-mail failed silently.");
        }
    }

    /** Step 2: user clicks confirmation link -> consume token and update e-mail. */
    public void confirm(String token) {
        EmailChangeTokenService.Payload payload = emailChangeTokenService.consume(token);
        UUID userId = payload.userId();
        String newEmail = payload.newEmail();

        // ensure not used by another account (race condition)
        Optional<User> existing = userRepository.findByEmail(newEmail);
        if (existing.isPresent() && !existing.get().getId().equals(userId)) {
            throw new IllegalArgumentException("E-mail is already registered");
        }

        // update email (mark confirmed true since link was verified)
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setEmail(newEmail);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        // notify the NEW email
        try {
            mailer.sendChanged(newEmail, user.getName());
        } catch (Exception e) {
            log.warn("[EMAIL CHANGE] notify changed failed: {}", e.getMessage());
        }
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

        String path = "email-change/confirm?token=" + urlEncode(token);
        return base.endsWith("/") ? base + path : base + "/" + path;
    }

    private static String urlEncode(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
