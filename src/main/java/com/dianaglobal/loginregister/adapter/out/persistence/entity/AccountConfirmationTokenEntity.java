package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Document("account_confirmation_tokens")
public class AccountConfirmationTokenEntity {

    @Id
    private UUID id;

    @Indexed
    private UUID userId;

    /** Salve apenas o hash do token (ex.: SHA-256 Base64Url) */
    @Indexed(unique = true)
    private String tokenHash;

    private Instant createdAt;
    /** Expiração absoluta; TTL criado via índice programático no TtlIndexRepair */
    private Instant expiresAt;

    /** Uso único */
    private Instant consumedAt;

    /** Revogação/validade atual */
    private boolean valid = true;

    public AccountConfirmationTokenEntity() {}

    // Getters/Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }

    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public Instant getConsumedAt() { return consumedAt; }
    public void setConsumedAt(Instant consumedAt) { this.consumedAt = consumedAt; }

    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }
}
