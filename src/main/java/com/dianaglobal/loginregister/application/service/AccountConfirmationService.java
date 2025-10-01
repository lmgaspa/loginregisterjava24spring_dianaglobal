// src/main/java/com/dianaglobal/loginregister/application/service/AccountConfirmationService.java
package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.mail.AccountConfirmationEmailService;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    /** Serviço responsável por criar/validar/consumir tokens de confirmação. */
    private final AccountConfirmationTokenService confirmationTokenService;

    /** Serviço de e-mail (HTML) para enviar o link de confirmação. */
    private final AccountConfirmationEmailService emailService;

    /** Validade (min) do token de confirmação. */
    @Value("${application.confirmation.minutes:45}")
    private int expirationMinutes;

    /**
     * Dispara (se existir usuário) um novo e-mail de confirmação.
     * Não vaza existência de e-mail para o chamador – qualquer erro é apenas logado.
     */
    public void requestConfirmation(String email, String frontendBaseUrl) {
        final String normalized = normalize(email);
        if (normalized == null) return;

        Optional<User> opt = userRepository.findByEmail(normalized);
        if (opt.isEmpty()) {
            // Não vazar existência de e-mail; apenas sair silenciosamente
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

    /**
     * Sobrecarga opcional caso você queira forçar um 'name' (ex.: quando o nome ainda não está salvo).
     * Evita conflito de variável local “link” usando outro identificador.
     */
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

        String confirmUrl = buildConfirmLink(frontendBaseUrl, token); // <- nome diferente de 'link' para evitar colisão
        try {
            String safeName = forceName ? (name == null ? "" : name) : user.getName();
            emailService.send(user.getEmail(), safeName, confirmUrl, expirationMinutes);
        } catch (Exception e) {
            log.warn("[CONFIRMATION] failed to send email to {}: {}", normalized, e.getMessage());
        }
    }

    /**
     * Confirma o token: valida, consome e marca o e-mail como confirmado.
     * Lança IllegalArgumentException para token inválido/expirado/já usado.
     */
    public void confirm(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Invalid confirmation token");
        }

        AccountConfirmationTokenService.ConfirmationPayload payload =
                confirmationTokenService.consume(token); // deve lançar se inválido/expirado/usado

        UUID userId = payload.userId();
        // Se seu UserRepositoryPort tiver um método específico:
        userRepository.markEmailConfirmed(userId);
        log.info("[CONFIRMATION] email confirmed for user {}", userId);
    }

    // ===== utils =====

    private static String normalize(String email) {
        if (email == null) return null;
        String e = email.trim().toLowerCase();
        return e.isBlank() ? null : e;
    }

    /**
     * Monta o link para a sua página pública de confirmação (Next.js)
     * Ex.: https://www.dianaglobal.com.br/confirm-account?token=...
     */
    private static String buildConfirmLink(String frontendBaseUrl, String token) {
        String base = (frontendBaseUrl == null || frontendBaseUrl.isBlank())
                ? "https://www.dianaglobal.com.br"
                : frontendBaseUrl.trim();

        // garante 1 barra antes do caminho
        if (base.endsWith("/")) {
            return base + "confirm-account?token=" + urlEncode(token);
        }
        return base + "/confirm-account?token=" + urlEncode(token);
    }

    private static String urlEncode(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
