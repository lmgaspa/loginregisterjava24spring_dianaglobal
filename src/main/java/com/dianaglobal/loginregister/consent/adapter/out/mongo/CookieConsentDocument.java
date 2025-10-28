package com.dianaglobal.loginregister.consent.adapter.out.mongo;

import com.dianaglobal.loginregister.consent.domain.ConsentDecision;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Document(collection = "cookie_consent_log")
@Data
@NoArgsConstructor
public class CookieConsentDocument {

    @Id
    private UUID id;                 // Mongo salva como BinData subtype 4 (UUID)

    @Indexed
    private UUID userId;            // opcional (pode ser null)

    private String version;         // ex.: "2025-10-01"
    private ConsentDecision decision;

    private boolean analytics;
    private boolean marketing;

    private String ip;
    private String userAgent;

    @Indexed
    private Instant createdAt;
}
