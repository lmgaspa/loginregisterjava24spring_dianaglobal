package com.dianaglobal.loginregister.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Helper class para gerenciar cookies de autenticação (refresh token e CSRF).
 * Centraliza a lógica de criação e gestão de cookies.
 */
@Slf4j
@Component
public class AuthenticationCookieHelper {

    private static final String COOKIE_REFRESH = "refresh_token";
    private static final String COOKIE_CSRF = "csrf_token";
    private static final String COOKIE_PATH = "/api/auth";
    private static final String SAME_SITE_NONE = "None";
    private static final String SAME_SITE_LAX = "Lax";
    private static final String HDR_SET_COOKIE = "Set-Cookie";

    private final boolean cookiesSecure;
    private final long refreshTtlDays;

    public AuthenticationCookieHelper(
            @Value("${application.cookies.secure:true}") boolean cookiesSecure,
            @Value("${application.auth.refresh-ttl-days:30}") long refreshTtlDays) {
        this.cookiesSecure = cookiesSecure;
        this.refreshTtlDays = refreshTtlDays;
    }

    /**
     * Define os cookies de autenticação (refresh token e CSRF) na resposta HTTP.
     */
    public void setAuthCookies(HttpServletResponse response, String refreshToken, String csrfToken) {
        long maxAge = Duration.ofDays(refreshTtlDays).getSeconds();
        ResponseCookie refreshCookie = buildRefreshCookie(refreshToken, maxAge, SAME_SITE_NONE);
        ResponseCookie csrfCookie = buildCsrfCookie(csrfToken, maxAge, SAME_SITE_NONE);
        
        response.addHeader(HDR_SET_COOKIE, refreshCookie.toString());
        response.addHeader(HDR_SET_COOKIE, csrfCookie.toString());
    }

    /**
     * Remove os cookies de autenticação da resposta HTTP.
     */
    public void clearAuthCookies(HttpServletResponse response) {
        ResponseCookie refreshCookie = buildRefreshCookie("", 0, SAME_SITE_LAX);
        ResponseCookie csrfCookie = buildCsrfCookie("", 0, SAME_SITE_LAX);
        
        response.addHeader(HDR_SET_COOKIE, refreshCookie.toString());
        response.addHeader(HDR_SET_COOKIE, csrfCookie.toString());
    }

    /**
     * Expõe o CSRF token no header da resposta para uso via JavaScript.
     */
    public void exposeCsrfHeader(HttpServletResponse response, String csrfToken) {
        response.addHeader("X-CSRF-Token", csrfToken);
        response.addHeader("Access-Control-Expose-Headers", "X-CSRF-Token");
    }

    private ResponseCookie buildRefreshCookie(String token, long maxAgeSeconds, String sameSite) {
        return ResponseCookie.from(COOKIE_REFRESH, token == null ? "" : token)
                .httpOnly(true)
                .secure(cookiesSecure)
                .sameSite(sameSite)
                .path(COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .build();
    }

    private ResponseCookie buildCsrfCookie(String token, long maxAgeSeconds, String sameSite) {
        return ResponseCookie.from(COOKIE_CSRF, token == null ? "" : token)
                .httpOnly(false)
                .secure(cookiesSecure)
                .sameSite(sameSite)
                .path(COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .build();
    }

    public String getRefreshCookieName() {
        return COOKIE_REFRESH;
    }

    public String getCsrfCookieName() {
        return COOKIE_CSRF;
    }
}

