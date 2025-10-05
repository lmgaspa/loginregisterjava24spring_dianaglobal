package com.dianaglobal.loginregister.consent.domain;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.util.UUID;

@Value @Builder
public class CookieConsent {
    UUID id;
    UUID userId;                 // pode ser null (anônimo)
    String version;              // ex.: "2025-10-01"
    ConsentDecision decision;    // accept_all | reject_all | custom
    ConsentCategories categories;
    String ip;                   // avalie minimização
    String userAgent;            // avalie minimização
    Instant createdAt;
}
