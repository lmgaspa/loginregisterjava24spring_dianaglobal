package com.dianaglobal.loginregister.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // stateless API (JWT, nada de sessão server-side)
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // CSRF padrão do Spring desabilitado.
                // A gente faz CSRF manualmente via header X-CSRF-Token + cookie httpOnly.
                .csrf(AbstractHttpConfigurer::disable)

                // CORS usa o bean corsConfigurationSource() lá embaixo
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(auth -> auth
                        // liberar todas as preflight OPTIONS
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // swagger / docs públicos (se você expõe isso)
                        .requestMatchers(
                                "/",
                                "/api/privacy/**",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/swagger",
                                "/api-docs",
                                "/api-docs/**"
                        ).permitAll()

                        // --- ROTAS PÚBLICAS DA V1 ---
                        // login/register/oauth/refresh/etc (exceto /profile que é protegido)
                        .requestMatchers(
                                "/api/v1/auth/login",
                                "/api/v1/auth/register",
                                "/api/v1/auth/oauth/google",
                                "/api/v1/auth/forgot-password",
                                "/api/v1/auth/reset-password",
                                "/api/v1/auth/confirm/resend",
                                "/api/v1/auth/confirmed", // GET para verificar status de confirmação (público)
                                "/api/v1/auth/refresh-token"
                        ).permitAll()

                        // confirmação de conta (request link, resend, verify)
                        .requestMatchers("/api/v1/confirm/**").permitAll()

                        // --- ROTAS PROTEGIDAS ---
                        // /api/v1/auth/profile e outros endpoints protegidos precisam de autenticação
                        // tudo o resto precisa de JWT válido
                        .anyRequest().authenticated()
                )

                // injeta seu filtro JWT pra validar Authorization: Bearer <token>
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();

        // domínios que podem chamar sua API
        // IMPORTANTE: quando allowCredentials=true, use setAllowedOrigins (não setAllowedOriginPatterns)
        cfg.setAllowedOrigins(List.of(
                "https://www.dianaglobal.com.br",
                "https://dianaglobal.com.br",
                "http://localhost:3000" // dev local
        ));

        // métodos liberados
        cfg.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));

        // headers que o front-end pode mandar
        cfg.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-CSRF-Token",
                "X-Requested-With",
                "Origin"
        ));

        // permitir cookies (refresh_token httpOnly + csrf_token)
        cfg.setAllowCredentials(true);

        // headers que o browser PODE ENXERGAR na resposta (ex: nosso X-CSRF-Token)
        cfg.setExposedHeaders(List.of("X-CSRF-Token"));

        // cache do preflight
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
