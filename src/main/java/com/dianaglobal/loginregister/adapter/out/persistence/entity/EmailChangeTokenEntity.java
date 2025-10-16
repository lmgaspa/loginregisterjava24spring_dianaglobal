package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
@Document("email_change_tokens")
public class EmailChangeTokenEntity {

    @Id
    private UUID id;

    @Indexed
    private UUID userId;

    @Indexed(unique = true)
    private String tokenHash;           // hash do token (ex.: SHA-256 Base64Url)

    @Indexed
    private String newEmailNormalized;  // novo e-mail normalizado (lower/trim)

    private Instant createdAt;
    private Instant expiresAt;          // TTL por índice programático (TtlIndexRepair)
    private Instant consumedAt;         // usado/consumido em que momento
    @Builder.Default
    private boolean valid = true;       // revogado/uso único
}
