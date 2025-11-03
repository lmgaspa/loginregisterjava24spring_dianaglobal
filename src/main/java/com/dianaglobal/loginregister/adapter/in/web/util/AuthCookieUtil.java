package com.dianaglobal.loginregister.adapter.in.web.util;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class AuthCookieUtil {

    // nomes e headers iguais ao AuthController original
    private static final String HDR_SET_COOKIE = HttpHeaders.SET_COOKIE;
    private static final String HDR_EXPOSE = "Access-Control-Expose-Headers";
    private static final String HDR_CSRF = "X-CSRF-Token";
    private static final String COOKIE_REFRESH = "refresh_token";
    private static final String COOKIE_CSRF = "csrf_token";
    private static final String COOKIE_PATH = "/api/auth";
    private static final String SAME_SITE_NONE = "None";
    private static final String SAME_SITE_LAX = "Lax";

    @Value("${application.cookies.secure:true}")
    private boolean cookiesSecure;

    @Value("${application.auth.refresh-ttl-days:30}")
    private long refreshTtlDays;

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
                .httpOnly(false)          // front precisa ler pra mandar no header X-CSRF-Token
                .secure(cookiesSecure)
                .sameSite(sameSite)
                .path(COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .build();
    }

    public void setAuthCookies(HttpServletResponse response, String refreshToken, String csrfToken) {
        long maxAge = Duration.ofDays(refreshTtlDays).getSeconds();
        ResponseCookie refreshCookie = buildRefreshCookie(refreshToken, maxAge, SAME_SITE_NONE);
        ResponseCookie csrfCookie    = buildCsrfCookie(csrfToken, maxAge, SAME_SITE_NONE);

        response.addHeader(HDR_SET_COOKIE, refreshCookie.toString());
        response.addHeader(HDR_SET_COOKIE, csrfCookie.toString());
    }

    public void clearAuthCookies(HttpServletResponse response) {
        ResponseCookie refreshCookie = buildRefreshCookie("", 0, SAME_SITE_LAX);
        ResponseCookie csrfCookie    = buildCsrfCookie("", 0, SAME_SITE_LAX);

        response.addHeader(HDR_SET_COOKIE, refreshCookie.toString());
        response.addHeader(HDR_SET_COOKIE, csrfCookie.toString());
    }

    public void exposeCsrfHeader(HttpServletResponse response, String csrfToken) {
        response.addHeader(HDR_CSRF, csrfToken);
        response.addHeader(HDR_EXPOSE, HDR_CSRF);
    }
}
