package com.dianaglobal.loginregister.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class CsrfTokenService {

    public static final String CSRF_COOKIE_NAME = "csrf_token";

    @Value("${security.csrf.max-age-hours:8}")
    private long maxAgeHours;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Gera um token CSRF aleatório. O parâmetro 'subject' existe apenas para manter a assinatura
     * esperada pelo seu AuthController (e pode ser ignorado).
     */
    public String generateCsrfToken(String subject) {
        byte[] random = new byte[24];
        secureRandom.nextBytes(random);
        // opcional: misturar alguns bytes do subject
        if (subject != null) {
            byte[] s = subject.getBytes();
            for (int i = 0; i < Math.min(s.length, random.length); i++) {
                random[i] ^= s[i];
            }
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    /**
     * Validação bem simples: apenas verifica se não é nulo/vazio.
     * OBS: o seu controller pode comparar header vs cookie.
     * Esse método existe para satisfazer a chamada validateCsrfToken(String) do seu AuthController.
     */
    public boolean validateCsrfToken(String token) {
        return token != null && !token.isBlank();
    }

    /** Validação útil quando você compara o header com o cookie enviado ao browser. */
    public boolean validateCsrfToken(String headerToken, String cookieToken) {
        return headerToken != null && !headerToken.isBlank()
                && headerToken.equals(cookieToken);
    }

    /** Monta o cookie do CSRF (não HttpOnly, para o front poder ler e mandar no header). */
    public ResponseCookie buildCsrfCookie(String token, boolean secure) {
        return ResponseCookie.from(CSRF_COOKIE_NAME, token)
                .httpOnly(false)               // o front precisa ler para mandar no header
                .secure(secure)                 // true em produção HTTPS
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofHours(maxAgeHours))
                .build();
    }
}
