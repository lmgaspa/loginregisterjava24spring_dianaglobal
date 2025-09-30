package com.dianaglobal.loginregister.config;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;

@Configuration
public class GoogleVerifierConfig {

    /**
     * Só cria o bean quando google.oauth.enabled=true.
     * GOOGLE_CLIENT_ID vem do ambiente; default vazio evita PlaceholderResolutionException.
     */
    @Bean
    @ConditionalOnProperty(name = "google.oauth.enabled", havingValue = "true", matchIfMissing = false)
    public GoogleIdTokenVerifier googleTokenVerifier(
            @Value("${GOOGLE_CLIENT_ID:}") String clientId
    ) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("google.oauth.enabled=true, mas GOOGLE_CLIENT_ID não foi configurado.");
        }
        return new GoogleIdTokenVerifier
                .Builder(new NetHttpTransport(), new GsonFactory())
                .setAudience(Collections.singletonList(clientId))
                .build();
    }
}
