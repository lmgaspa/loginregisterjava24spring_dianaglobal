// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/entity/EmailChangeTokenEntity.java
package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("email_change_tokens")
public class EmailChangeTokenEntity {
    @Id
    private UUID id;

    @Indexed
    private UUID userId;

    @Indexed(unique = true)
    private String tokenHash;

    @Indexed
    private String newEmailNormalized;

    private Instant createdAt;
    private Instant expiresAt;
    private Instant consumedAt;

    @Indexed
    private Boolean valid; // usar Boolean para null-safety (TRUE/FALSE)

    public boolean isValid() {
        return Boolean.TRUE.equals(valid);
    }
}
