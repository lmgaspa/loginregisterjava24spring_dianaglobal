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
                // API stateless (usamos JWT)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // CSRF do Spring desabilitado (você valida CSRF manualmente no /refresh-token via header)
                .csrf(AbstractHttpConfigurer::disable)

                // CORS conforme bean abaixo
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(auth -> auth
                        // preflight
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // swagger + springdoc (se usar)
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

                        // Endpoints de autenticação precisam estar públicos
                        .requestMatchers("/api/auth/**").permitAll()

                        // demais rotas exigem autenticação JWT
                        .anyRequest().authenticated()
                )

                // seu filtro JWT antes do UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();

        // NUNCA use "*" com allowCredentials=true. Liste os domínios.
        cfg.setAllowedOriginPatterns(List.of(
                "https://www.dianaglobal.com.br",
                "https://dianaglobal.com.br",
                "http://localhost:3000" // dev
        ));

        // Métodos aceitos
        cfg.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));

        // Headers aceitos pelo backend (inclua Authorization e seu header de CSRF)
        cfg.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-CSRF-Token",
                "X-Requested-With",
                "Origin"
        ));

        // Cookies cross-site
        cfg.setAllowCredentials(true);

        // Expor headers não é necessário para Set-Cookie (o browser processa sozinho),
        // mas pode expor Authorization se você enviar em respostas (não é o caso usual):
        // cfg.setExposedHeaders(List.of("Authorization"));

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
