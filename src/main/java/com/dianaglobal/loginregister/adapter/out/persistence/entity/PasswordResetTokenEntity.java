package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.UUID;

// password_reset_tokens
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "password_reset_tokens")
public class PasswordResetTokenEntity {

    @Id
    private UUID id;

    @Indexed
    private UUID userId;

    /** SHA-256 (URL-safe) do token em texto puro */
    @Indexed(unique = true)
    private String tokenHash;

    /** Expira exatamente neste horário */
    @Indexed(name = "password_reset_expires_ttl", expireAfter = "PT0S")
    private Date expiresAt;

    private Date usedAt;

    @Builder.Default
    private Date createdAt = new Date();
}
