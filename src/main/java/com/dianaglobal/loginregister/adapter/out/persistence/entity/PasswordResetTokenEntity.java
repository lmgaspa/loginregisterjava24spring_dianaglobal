package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.UUID;

@Document("password_reset_tokens")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PasswordResetTokenEntity {
    @Id private UUID id;

    private UUID userId;

    /** Hash SHA-256 em Base64URL do token bruto (não salvar o token em claro) */
    @Indexed(unique = true)
    private String tokenHash;

    @Indexed private Date expiresAt;
    private Date usedAt;
    private Date createdAt;
}
