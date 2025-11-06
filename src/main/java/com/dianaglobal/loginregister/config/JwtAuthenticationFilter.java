package com.dianaglobal.loginregister.config;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.dianaglobal.loginregister.application.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    private static boolean isPublicAuthPath(String path, String method) {
        // somente estes endpoints não exigem JWT (usando /api/v1/auth conforme controllers):
        return
                path.equals("/api/v1/auth/login") ||
                        path.equals("/api/v1/auth/register") ||
                        path.equals("/api/v1/auth/confirm-account") ||
                        path.equals("/api/v1/auth/confirm/resend") ||
                        path.equals("/api/v1/auth/forgot-password") ||
                        path.equals("/api/v1/auth/reset-password") ||
                        path.equals("/api/v1/auth/oauth/google") ||
                        // confirmação de conta em /api/v1/confirm
                        path.equals("/api/v1/confirm/request") ||
                        path.equals("/api/v1/confirm/verify") ||
                        path.equals("/api/v1/confirm/resend"); // se exposto
        // OBS: /api/v1/auth/profile NÃO entra aqui (é protegido)
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String method = request.getMethod();
        String path = request.getServletPath();

        // Preflight CORS
        if ("OPTIONS".equalsIgnoreCase(method)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Rotas públicas (não autenticadas)
        if (isPublicAuthPath(path, method)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Para rotas protegidas, exigir Authorization header
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("[JWT FILTER] Missing Authorization header for {} {} - Header: {}", 
                    method, path, authHeader != null ? "present but invalid format" : "missing");
            // Rotas protegidas sem token -> retornar 401
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Missing or invalid authentication token\"}");
            return;
        }

        final String jwt = authHeader.substring(7);
        log.info("[JWT FILTER] Processing token for {} {} - Token length: {}, Token preview: {}...", 
                method, path, jwt.length(), jwt.length() > 20 ? jwt.substring(0, 20) : jwt);

        try {
            final String email = jwtService.extractEmail(jwt);
            log.info("[JWT FILTER] Extracted email: {} for {} {}", email, method, path);

            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    log.info("[JWT FILTER] Token valid for {} {}", email, path);
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    // Token inválido (não expirado, mas inválido)
                    log.warn("[JWT FILTER] Token invalid for {} {} - Email: {}", method, path, email);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid authentication token\"}");
                    return;
                }
            } else {
                // Não conseguiu extrair email do token (token malformado)
                log.warn("[JWT FILTER] Could not extract email from token for {} {} - Email extracted: {}", method, path, email);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid authentication token\"}");
                return;
            }

            filterChain.doFilter(request, response);

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.warn("[JWT FILTER] Expired token for {} {} - Email: {}", method, path, e.getClaims().getSubject());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Token expired. Please login again.\"}");
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.warn("[JWT FILTER] Invalid signature for {} {} - Error: {}", method, path, e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid token signature\"}");
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            log.warn("[JWT FILTER] Malformed token for {} {} - Error: {}", method, path, e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Malformed token\"}");
        } catch (Exception e) {
            // Qualquer outro erro (token malformado, assinatura inválida, etc)
            log.error("[JWT FILTER] Token validation error for {} {} - Error: {} - Class: {}", 
                    method, path, e.getMessage(), e.getClass().getSimpleName(), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid authentication token\"}");
        }
    }
}
