package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.UUID;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
@Document(collection = "account_confirmation_tokens")
public class AccountConfirmationTokenEntity {

    @Id
    private UUID id;

    @Indexed
    private UUID userId;

    /** Armazene apenas o hash; torne-o único para evitar colisões acidentais */
    @Indexed(unique = true)
    private String tokenHash;

    @Builder.Default
    private Date createdAt = new Date();

    /** TTL do Mongo: expira exatamente neste horário */
    @Indexed(name = "account_confirm_expires_ttl", expireAfter = "PT0S")
    private Date expiresAt;

    private Date usedAt;
}
