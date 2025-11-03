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
                // Stateless API (JWT em vez de sessão Http)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // CSRF nativo desativado (você faz CSRF manual: header X-CSRF-Token vs cookie csrf_token)
                .csrf(AbstractHttpConfigurer::disable)

                // CORS config abaixo
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(auth -> auth
                        // Preflight
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Swagger / docs / health / privacy público (ajuste se quiser trancar depois)
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

                        // Toda autenticação pública (login, register, forgot-password, refresh-token etc.)
                        .requestMatchers(ApiPaths.AUTH_BASE + "/**").permitAll()

                        // Qualquer outra rota exige JWT válido
                        .anyRequest().authenticated()
                )

                // seu filtro JWT roda antes do UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();

        // domínios autorizados (ajusta conforme produção)
        cfg.setAllowedOriginPatterns(List.of(
                "https://www.dianaglobal.com.br",
                "https://dianaglobal.com.br",
                "http://localhost:3000"
        ));

        cfg.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));

        cfg.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-CSRF-Token",
                "X-Requested-With",
                "Origin"
        ));

        // precisamos mandar cookies (refresh_token, csrf_token)
        cfg.setAllowCredentials(true);

        // expor header pro browser conseguir ler o novo CSRF e salvar no cookie JS
        cfg.setExposedHeaders(List.of("X-CSRF-Token"));

        // cache do preflight em segundos
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
