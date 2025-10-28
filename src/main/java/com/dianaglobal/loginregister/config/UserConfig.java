package com.dianaglobal.loginregister.config;

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class UserConfig {

    private final UserRepositoryPort userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .map(user -> {
                    // Para usuários Google OAuth que ainda não setaram senha,
                    // usar uma senha dummy que nunca será validada via password
                    String password = user.getPassword();
                    if ("GOOGLE".equalsIgnoreCase(user.getAuthProvider()) && !user.isPasswordSet()) {
                        // Usar senha dummy que nunca será usada para login por senha
                        password = "{noop}dummy-google-oauth-user";
                    }
                    
                    return (UserDetails) org.springframework.security.core.userdetails.User
                            .withUsername(user.getEmail())
                            .password(password)
                            .authorities(Collections.emptyList()) // ou .roles("USER")
                            .build();
                })
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
