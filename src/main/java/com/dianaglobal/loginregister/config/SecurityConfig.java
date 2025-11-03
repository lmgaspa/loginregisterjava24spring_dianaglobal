package com.dianaglobal.loginregister.config;

import java.util.List;

import lombok.RequiredArgsConstructor;
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

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // API stateless (JWT, sem sessão server-side)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // CSRF nativo do Spring desativado.
                // Você já faz proteção CSRF manual (token no header + cookie) nos POST/PUT protegidos.
                .csrf(AbstractHttpConfigurer::disable)

                // Habilita CORS usando o bean corsConfigurationSource() lá embaixo
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(auth -> auth
                        // Preflight OPTIONS sempre liberado
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Swagger / health / privacy etc. público
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

                        // 🔓 Endpoints públicos de auth/conta (com e sem /v1/)
                        // login, register, forgot-password, reset-password,
                        // refresh-token (usa refresh cookie httpOnly),
                        // confirm (confirmar conta / resend),
                        // email confirmation verify etc.
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers("/api/confirm/**").permitAll()
                        .requestMatchers("/api/v1/confirm/**").permitAll()

                        // qualquer coisa que sobrou exige JWT válido
                        .anyRequest().authenticated()
                )

                // coloca seu filtro JWT antes do UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();

        // Domínios FRONTEND autorizados a chamar o backend
        cfg.setAllowedOriginPatterns(List.of(
                "https://www.dianaglobal.com.br",
                "https://dianaglobal.com.br",
                "http://localhost:3000" // dev local
        ));

        // Métodos HTTP permitidos no CORS
        cfg.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));

        // Cabeçalhos que o browser pode mandar pro backend
        cfg.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-CSRF-Token",
                "X-Requested-With",
                "Origin"
        ));

        // MUITO IMPORTANTE: permitir cookies (refresh-token cookie httpOnly)
        cfg.setAllowCredentials(true);

        // Cabeçalhos que o browser pode ENXERGAR na resposta
        // (precisamos expor o X-CSRF-Token pro front salvar de volta)
        cfg.setExposedHeaders(List.of("X-CSRF-Token"));

        // Cache do preflight no browser
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
